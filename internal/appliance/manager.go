package appliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// apiError converts err for callers of API, keeping nil untyped: a nil
// *Error in an error interface isn't nil.
func apiError(err error) error {
	if err == nil {
		return nil
	}
	return AsError(err)
}

// modelFile is the name the model has in the file registry.
const modelFile = "config.json"

// commandTimeout bounds commits and reverts, which run system commands.
const commandTimeout = 2 * time.Minute

// Manager implements API on top of the commit engine.
type Manager struct {
	store *config.Store
	// mu makes stage-then-commit sequences atomic with respect to each
	// other; the store has its own lock for its internals.
	mu sync.Mutex

	onChange func()
	leases   *leases.Watcher
}

// SetLeaseWatcher gives LeaseNames the watcher to report on. Set it
// before serving.
func (m *Manager) SetLeaseWatcher(w *leases.Watcher) { m.leases = w }

// LeaseNames reports what the lease watcher last did. It doesn't take
// the lock: the watcher has its own.
func (m *Manager) LeaseNames() (*LeaseNames, error) {
	out := &LeaseNames{Registered: []LeaseName{}, Refused: []RefusedName{}}
	if m.leases == nil {
		return out, nil
	}
	st := m.leases.State()
	out.Enabled, out.Error = st.Enabled, st.Error
	if !st.Checked.IsZero() {
		out.Checked = &st.Checked
	}
	for _, r := range st.Registered {
		if len(out.Registered) == MaxLeaseNames {
			out.Truncated = true
			break
		}
		out.Registered = append(out.Registered, LeaseName{strings.TrimSuffix(r.Name, "."), r.IP.String()})
	}
	for _, r := range st.Refused {
		if len(out.Refused) == MaxLeaseNames {
			out.Truncated = true
			break
		}
		out.Refused = append(out.Refused, RefusedName{r.IP.String(), displayable(r.Hostname), r.Reason})
	}
	return out, nil
}

// displayable makes a client-chosen hostname safe to show: invalid
// UTF-8 and anything not printable (control characters, and format
// characters such as bidi overrides that could make it read as another
// name) become U+FFFD, and it's cut to MaxHostnameRunes.
func displayable(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == MaxHostnameRunes {
			b.WriteString("…")
			break
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// OnChange sets a function called, without the lock held, after each
// commit or revert has been attempted: something the system runs may
// have been reloaded. Set it before serving.
func (m *Manager) OnChange(f func()) { m.onChange = f }

func (m *Manager) changed() {
	if m.onChange != nil {
		m.onChange()
	}
}

var _ API = (*Manager)(nil)

// New returns a Manager. The store's registry must include the model
// file (config.DefaultFiles does).
func New(store *config.Store) (*Manager, error) {
	f, err := store.Lookup(modelFile)
	if err != nil || f.Path != config.ModelPath {
		return nil, fmt.Errorf("appliance: the file registry has no %s at %s", modelFile, config.ModelPath)
	}
	return &Manager{store: store}, nil
}

// EncodeModel is the model file's exact contents for a model.
func EncodeModel(m *pf.Model) ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeModel(data []byte) (*pf.Model, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m pf.Model
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func version(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:10])
}

// live returns the committed model, or nil if there's none yet.
func (m *Manager) live() (*pf.Model, string, error) {
	data, exists, err := m.store.Live(modelFile)
	if err != nil || !exists {
		return nil, NoVersion, err
	}
	model, err := decodeModel(data)
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", config.ModelPath, err)
	}
	return model, version(data), nil
}

func (m *Manager) Live() (*Config, error) {
	model, v, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	if model == nil {
		model = &pf.Model{}
	}
	return &Config{Version: v, Model: model}, nil
}

// stagedModel returns the staged model's contents. When only generated
// files are staged (re-applying the live model over files changed
// outside OPF), it's the live model.
func (m *Manager) stagedModel() (data []byte, staged bool, err error) {
	data, staged, err = m.store.Staged(modelFile)
	if err != nil || staged {
		return data, staged, err
	}
	changes, err := m.store.Changes()
	if err != nil || len(changes) == 0 {
		return nil, false, err
	}
	data, exists, err := m.store.Live(modelFile)
	if err != nil || !exists {
		return nil, false, err
	}
	return data, true, nil
}

func (m *Manager) Status() (*Status, error) {
	_, live, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	st := &Status{Live: live}
	if data, staged, err := m.stagedModel(); err != nil {
		return nil, apiError(err)
	} else if staged {
		st.Staged = version(data)
	}
	if p := m.store.Pending(); p != nil {
		st.Pending = commitOf(p)
	}
	return st, nil
}

func (m *Manager) Staged() (*Staged, error) {
	s, err := m.staged()
	return s, apiError(err)
}

func (m *Manager) staged() (*Staged, error) {
	data, staged, err := m.stagedModel()
	if err != nil {
		return nil, err
	}
	if !staged {
		return nil, errorf(CodeNothingStaged, "nothing is staged")
	}
	model, err := decodeModel(data)
	if err != nil {
		return nil, fmt.Errorf("reading the staged model: %w", err)
	}
	_, live, err := m.live()
	if err != nil {
		return nil, err
	}
	changes, err := m.changes()
	if err != nil {
		return nil, err
	}
	return &Staged{Version: version(data), Base: live, Model: model, Changes: changes}, nil
}

func (m *Manager) changes() ([]FileChange, error) {
	cs, err := m.store.Changes()
	if err != nil {
		return nil, err
	}
	out := []FileChange{}
	for _, c := range cs {
		_, exists, err := m.store.Live(c.File.Name)
		if err != nil {
			return nil, err
		}
		status := "modified"
		if !exists {
			status = "added"
		}
		out = append(out, FileChange{
			Path: c.File.Path, Status: status, Diff: c.Diff, NeedsConfirm: c.File.Confirm,
			Model: c.File.Name == modelFile, ModifiedOutside: c.Drifted,
		})
	}
	return out, nil
}

func (m *Manager) Stage(req StageRequest) (*Staged, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.stage(req)
	return s, apiError(err)
}

func (m *Manager) stage(req StageRequest) (*Staged, error) {
	if m.store.Pending() != nil {
		return nil, errorf(CodePending, "a commit is waiting for confirmation; confirm or revert it first")
	}
	liveModel, liveVersion, err := m.live()
	if err != nil {
		return nil, err
	}
	if req.Base != liveVersion {
		return nil, errorf(CodeConflict, "the configuration was changed (now %s, you started from %s); reload and redo your changes", liveVersion, req.Base)
	}
	if req.Model == nil {
		return nil, errorf(CodeInvalid, "no model")
	}
	if errs := pf.Validate(req.Model); len(errs) > 0 {
		e := errorf(CodeInvalid, "the configuration has %d problem(s)", len(errs))
		for _, fe := range errs {
			e.Details = append(e.Details, Detail{Path: fe.Path, Message: fe.Message})
		}
		return nil, e
	}
	data, err := EncodeModel(req.Model)
	if err != nil {
		return nil, err
	}

	gen := generated(req.Model)
	liveGen := map[string]string{}
	if liveModel != nil {
		liveGen = generated(liveModel)
	}
	var problems []Detail
	var removed []Detail
	type file struct {
		f       config.File
		content []byte
	}
	var files []file
	for path, content := range gen {
		f, err := m.store.LookupPath(path)
		if err != nil {
			return nil, fmt.Errorf("the generator wrote %s, which isn't a managed file: %w", path, err)
		}
		files = append(files, file{f, []byte(content)})
		disk, onDisk, err := m.store.Live(f.Name)
		if err != nil {
			return nil, err
		}
		want := config.Normalize([]byte(content))
		if onDisk && bytes.Equal(disk, want) {
			continue // no change to this file
		}
		// What OPF last wrote there, if anything.
		prev, known := liveGen[path]
		outside := onDisk != known || (known && !bytes.Equal(disk, config.Normalize([]byte(prev))))
		if outside && !slices.Contains(req.Overwrite, path) {
			problems = append(problems, Detail{Path: path, Message: "changed outside OPF; list it in overwrite to replace it"})
		}
	}
	for path := range liveGen {
		if _, still := gen[path]; still {
			continue
		}
		f, err := m.store.LookupPath(path)
		if err != nil {
			continue
		}
		if _, onDisk, err := m.store.Live(f.Name); err == nil && onDisk {
			removed = append(removed, Detail{Path: path, Message: "would have to be removed, which OPF can't do yet"})
		}
	}
	if len(problems) > 0 {
		sortDetails(problems)
		return nil, &Error{Code: CodeModifiedOutside, Message: "some files were changed outside OPF", Details: problems}
	}
	if len(removed) > 0 {
		sortDetails(removed)
		return nil, &Error{Code: CodeUnsupported, Message: "the change removes files, which isn't supported yet", Details: removed}
	}

	// Stage the whole set or nothing.
	if err := m.store.DiscardAll(); err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.f.Path, b.f.Path) })
	for _, f := range append([]file{{f: mustLookup(m.store, modelFile), content: data}}, files...) {
		if err := m.store.Stage(f.f.Name, f.content); err != nil {
			m.store.DiscardAll()
			if errors.Is(err, config.ErrPending) {
				return nil, errorf(CodePending, "a commit is waiting for confirmation")
			}
			return nil, err
		}
	}
	if _, staged, err := m.stagedModel(); err != nil {
		return nil, err
	} else if !staged {
		// Identical to what's live: nothing to commit.
		return &Staged{Version: liveVersion, Base: liveVersion, Model: req.Model, Changes: []FileChange{}}, nil
	}
	return m.staged()
}

func generated(model *pf.Model) map[string]string {
	out := map[string]string{}
	for _, f := range pf.GenerateFiles(model) {
		out[f.Path] = f.Content
	}
	return out
}

func mustLookup(s *config.Store, name string) config.File {
	f, err := s.Lookup(name)
	if err != nil {
		panic(err) // checked in New
	}
	return f
}

func sortDetails(d []Detail) {
	slices.SortFunc(d, func(a, b Detail) int { return strings.Compare(a.Path, b.Path) })
}

func (m *Manager) Discard() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store.Pending() != nil {
		return errorf(CodePending, "a commit is waiting for confirmation; its changes come back if it's reverted")
	}
	return apiError(m.store.DiscardAll())
}

// checkNotes validates the human description of a commit. It's stored
// in history and shown in the UI, so it's limited in size and kept to
// printable text.
func checkNotes(req CommitRequest) *Error {
	e := errorf(CodeInvalid, "the commit description is invalid")
	textOK := func(s string, max int) bool {
		return utf8.ValidString(s) && len(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
	}
	if !textOK(req.Message, 500) {
		e.Details = append(e.Details, Detail{Path: "message", Message: "must be at most 500 bytes of text without line breaks"})
	}
	if len(req.Changes) > 500 {
		e.Details = append(e.Details, Detail{Path: "changes", Message: "at most 500 changes"})
	}
	for i, c := range req.Changes {
		if !textOK(c.Area, 32) || !textOK(c.Summary, 300) {
			e.Details = append(e.Details, Detail{Path: fmt.Sprintf("changes[%d]", i), Message: "area (32 bytes) and summary (300 bytes) must be short text"})
		}
	}
	if len(e.Details) > 0 {
		return e
	}
	return nil
}

func (m *Manager) Commit(req CommitRequest) (*Commit, error) {
	defer m.changed() // after unlocking
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.commit(req)
	return c, apiError(err)
}

func (m *Manager) commit(req CommitRequest) (*Commit, error) {
	if e := checkNotes(req); e != nil {
		return nil, e
	}
	data, staged, err := m.stagedModel()
	if err != nil {
		return nil, err
	}
	if !staged {
		return nil, errorf(CodeNothingStaged, "nothing is staged")
	}
	if v := version(data); req.Staged != v {
		return nil, errorf(CodeConflict, "the staged configuration is %s, not %s; review it again", v, req.Staged)
	}
	// It was validated when staged; check again rather than trust the
	// file on disk.
	model, err := decodeModel(data)
	if err != nil {
		return nil, err
	}
	if errs := pf.Validate(model); len(errs) > 0 {
		return nil, errorf(CodeInvalid, "the staged configuration is no longer valid: %v", errs[0])
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	e, err := m.store.Commit(ctx, config.CommitInfo{Message: req.Message, Changes: req.Changes})
	var ce *config.CheckError
	var de *config.DriftError
	switch {
	case errors.As(err, &ce):
		return nil, &Error{Code: CodeCheckFailed, Message: ce.File + " was rejected by its validator; nothing was changed",
			Details: []Detail{{Path: ce.File, Output: ce.Output}}}
	case errors.As(err, &de):
		ce := &Error{Code: CodeModifiedOutside, Message: "files changed on disk after staging; stage again"}
		for _, f := range de.Files {
			ce.Details = append(ce.Details, Detail{Path: f})
		}
		return nil, ce
	case errors.Is(err, config.ErrPending):
		return nil, errorf(CodePending, "a commit is already waiting for confirmation")
	case errors.Is(err, config.ErrNoChanges):
		return nil, errorf(CodeNothingStaged, "nothing is staged")
	case err != nil && e != nil:
		// Applied, failed, and reverted: the commit exists in history
		// with status failed and its log says why.
		return commitOf(e), nil
	case err != nil:
		return nil, err
	}
	return commitOf(e), nil
}

func (m *Manager) Commits() ([]Commit, error) {
	entries, err := m.store.History()
	if err != nil {
		return nil, apiError(err)
	}
	out := make([]Commit, 0, len(entries))
	for _, e := range entries {
		out = append(out, *commitOf(e))
	}
	return out, nil
}

func (m *Manager) entry(id string) (*config.Entry, error) {
	e, err := m.store.Entry(id)
	if errors.Is(err, config.ErrUnknownCommit) {
		return nil, errorf(CodeNotFound, "no commit %q", id)
	}
	return e, err
}

func (m *Manager) GetCommit(id string) (*CommitDetail, error) {
	e, err := m.entry(id)
	if err != nil {
		return nil, apiError(err)
	}
	d := &CommitDetail{Commit: *commitOf(e), Diffs: []FileDiff{}, Log: e.Log}
	for _, f := range e.Files {
		diff, err := m.store.EntryDiff(id, f.Name)
		if err != nil {
			return nil, apiError(err)
		}
		d.Diffs = append(d.Diffs, FileDiff{Path: f.Path, Diff: diff})
	}
	return d, nil
}

// pendingIs checks that id is the commit waiting for confirmation.
func (m *Manager) pendingIs(id string) error {
	if _, err := m.entry(id); err != nil {
		return err
	}
	p := m.store.Pending()
	switch {
	case p == nil:
		return errorf(CodeNotPending, "commit %s isn't waiting for confirmation", id)
	case p.ID != id:
		return errorf(CodeNotPending, "commit %s is waiting for confirmation, not %s", p.ID, id)
	}
	return nil
}

func (m *Manager) Confirm(id string) (*Commit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pendingIs(id); err != nil {
		return nil, apiError(err)
	}
	if err := m.store.Confirm(); err != nil {
		if errors.Is(err, config.ErrNoPending) {
			return nil, errorf(CodeNotPending, "commit %s was reverted before it was confirmed", id)
		}
		return nil, apiError(err)
	}
	return m.commitByID(id)
}

func (m *Manager) Revert(id string) (*Commit, error) {
	defer m.changed() // after unlocking
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pendingIs(id); err != nil {
		return nil, apiError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	if err := m.store.Revert(ctx); err != nil {
		if errors.Is(err, config.ErrNoPending) {
			return nil, errorf(CodeNotPending, "commit %s was already reverted", id)
		}
		return nil, apiError(err)
	}
	return m.commitByID(id)
}

func (m *Manager) commitByID(id string) (*Commit, error) {
	e, err := m.entry(id)
	if err != nil {
		return nil, apiError(err)
	}
	return commitOf(e), nil
}

// CommitConfig returns the model as it was before or after a commit.
// It changes nothing: restoring is staging it, so it's validated and
// reviewed, and any objections dealt with, like any other change.
func (m *Manager) CommitConfig(id string, which Which) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.commitConfig(id, which)
	return c, apiError(err)
}

func (m *Manager) commitConfig(id string, which Which) (*Config, error) {
	if which != Before && which != After {
		return nil, errorf(CodeInvalid, "the configuration %q commit %s, rather than before or after?", which, id)
	}
	if _, err := m.entry(id); err != nil {
		return nil, err
	}
	data, exists, err := m.store.EntryContent(id, modelFile, which == Before)
	if errors.Is(err, config.ErrUnknownFile) {
		return nil, errorf(CodeUnsupported, "commit %s didn't change the configuration model", id)
	} else if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errorf(CodeUnsupported, "there was no configuration before commit %s", id)
	}
	model, err := decodeModel(data)
	if err != nil {
		return nil, fmt.Errorf("reading commit %s: %w", id, err)
	}
	return &Config{Version: version(data), Model: model}, nil
}

func commitOf(e *config.Entry) *Commit {
	c := &Commit{
		ID: e.ID, Time: e.Time, Status: CommitStatus(e.Status), Message: e.Message,
		Changes: e.Changes, Files: []CommitFile{},
	}
	if c.Changes == nil {
		c.Changes = []config.ChangeNote{}
	}
	if e.Status == config.StatusPending && !e.Deadline.IsZero() {
		d := e.Deadline
		c.Deadline = &d
	}
	for _, f := range e.Files {
		c.Files = append(c.Files, CommitFile{Path: f.Path, Created: !f.Existed, NeedsConfirm: f.Confirm, Model: f.Name == modelFile})
	}
	return c
}
