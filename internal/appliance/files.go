package appliance

import (
	"slices"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// ConfigFile is one of the files the configuration manages, for the
// Configuration files page: what the applied model generates, what's
// staged, and what a commit wrote.
type ConfigFile struct {
	Path string `json:"path"`
	// Desc is what the file is for, from the registry ("DHCP server").
	Desc   string `json:"desc"`
	Exists bool   `json:"exists"`
	Model  bool   `json:"model,omitempty"` // OPF's own config.json
	// Staged is what the staged changes do to it: added, modified or
	// removed; empty when they don't touch it.
	Staged string `json:"staged,omitempty"`
	// Outside means it was changed outside OPF: it differs from what OPF
	// last wrote there, which staging refuses to overwrite unasked.
	Outside bool `json:"outside,omitempty"`
	// Commit is the last commit that wrote it and is in effect.
	Commit *FileCommit `json:"commit,omitempty"`
}

// FileCommit is the commit that last wrote a file.
type FileCommit struct {
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// ConfigFileView is a file with its contents: as it is on disk, the
// staged change to it, and what changed outside OPF.
type ConfigFileView struct {
	ConfigFile
	Content     string `json:"content"`
	StagedDiff  string `json:"stagedDiff,omitempty"`
	OutsideDiff string `json:"outsideDiff,omitempty"`
}

// fileState is what Files and File work out from the model, the staged
// changes and history.
type fileState struct {
	liveGen map[string]string
	written map[string]writtenFile
	staged  map[string]config.Change
	commits map[string]*FileCommit
}

func (m *Manager) fileState() (*fileState, error) {
	liveModel, _, err := m.live()
	if err != nil {
		return nil, err
	}
	st := &fileState{liveGen: map[string]string{}, staged: map[string]config.Change{}, commits: map[string]*FileCommit{}}
	if liveModel != nil {
		st.liveGen = generated(liveModel)
		// Shared files are OPF's lines merged into what's there.
		if rc, _, err := m.store.Live(mustLookupPath(m.store, pf.RcPath).Name); err == nil {
			if merged, err := pf.MergeRcConfLocal(string(rc), liveModel); err == nil {
				st.liveGen[pf.RcPath] = merged
			}
		}
		if sc, _, err := m.store.Live(mustLookupPath(m.store, pf.SysctlPath).Name); err == nil {
			st.liveGen[pf.SysctlPath] = pf.MergeSysctlConf(string(sc), liveModel)
		}
		if h, _, err := m.store.Live(mustLookupPath(m.store, pf.HostsPath).Name); err == nil {
			st.liveGen[pf.HostsPath] = pf.MergeHosts(string(h), liveModel)
		}
		if data, err := EncodeModel(liveModel); err == nil {
			st.liveGen[config.ModelPath] = string(data)
		}
	}
	if st.written, err = m.lastWritten(); err != nil {
		return nil, err
	}
	changes, err := m.store.Changes()
	if err != nil {
		return nil, err
	}
	for _, c := range changes {
		st.staged[c.File.Path] = c
	}
	entries, err := m.store.History() // newest first
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Status != config.StatusApplied && e.Status != config.StatusConfirmed && e.Status != config.StatusPending {
			continue // reverted, failed: what it wrote isn't there
		}
		for _, f := range e.Files {
			if _, seen := st.commits[f.Path]; !seen {
				st.commits[f.Path] = &FileCommit{ID: e.ID, Time: e.Time, Message: e.Message}
			}
		}
	}
	return st, nil
}

// paths are the files the configuration manages: what the applied model
// generates, what's staged, and what a commit wrote and hasn't removed.
func (st *fileState) paths() []string {
	set := map[string]bool{}
	for p := range st.liveGen {
		set[p] = true
	}
	for p := range st.staged {
		set[p] = true
	}
	for p, w := range st.written {
		if w.exists {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func (m *Manager) describeFile(st *fileState, path string) (*ConfigFile, config.File, []byte, bool, error) {
	f, err := m.store.LookupPath(path)
	if err != nil {
		return nil, f, nil, false, err
	}
	disk, onDisk, err := m.store.Live(f.Name)
	if err != nil {
		return nil, f, nil, false, err
	}
	cf := &ConfigFile{Path: path, Desc: f.Desc, Exists: onDisk, Model: f.Name == modelFile, Commit: st.commits[path]}
	if c, ok := st.staged[path]; ok {
		switch {
		case c.Removed:
			cf.Staged = "removed"
		case onDisk:
			cf.Staged = "modified"
		default:
			cf.Staged = "added"
		}
	}
	_, _, cf.Outside = outsideChange(path, disk, onDisk, st.written, st.liveGen)
	return cf, f, disk, onDisk, nil
}

// Files lists the files the configuration manages.
func (m *Manager) Files() ([]ConfigFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.fileState()
	if err != nil {
		return nil, apiError(err)
	}
	out := []ConfigFile{}
	for _, p := range st.paths() {
		cf, _, _, _, err := m.describeFile(st, p)
		if err != nil {
			continue // not a managed path: nothing to show
		}
		out = append(out, *cf)
	}
	return out, nil
}

// File is one managed file with its contents. Only the files Files
// lists can be read: never an arbitrary path.
func (m *Manager) File(path string) (*ConfigFileView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.fileState()
	if err != nil {
		return nil, apiError(err)
	}
	if !slices.Contains(st.paths(), path) {
		return nil, errorf(CodeNotFound, "%s isn't one of the files this configuration manages", path)
	}
	cf, f, disk, _, err := m.describeFile(st, path)
	if err != nil {
		return nil, errorf(CodeNotFound, "%s isn't one of the files this configuration manages", path)
	}
	v := &ConfigFileView{ConfigFile: *cf, Content: string(disk)}
	if c, ok := st.staged[path]; ok {
		v.StagedDiff = c.Diff
	}
	if cf.Outside {
		prev, _, _ := outsideChange(path, disk, cf.Exists, st.written, st.liveGen)
		if d, err := m.store.DiffWith(f.Name, config.Normalize(prev), path+" (as OPF left it)", path+" (now)"); err == nil {
			v.OutsideDiff = strings.TrimRight(d, "\n") + "\n"
		}
	}
	return v, nil
}
