package appliance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Taking a machine over (System › Take over): OPF imports the machine's
// own configuration (pf.Import), shows what it understood and what the
// first commit would change, and on the admin's word stages the import
// as its first change, to be reviewed and committed like any other.
// Nothing on the machine changes until that commit.
//
// Read-only, OPF can't stage (its sandbox) or leave read-only mode in
// place (unveil can't be widened), so the import is saved in the state
// directory (TakeOverFile) and OPF starts again without -readonly:
// cmd/opf removes -readonly from rc.conf.local's opf_flags, stages the
// import (ResumeTakeOver) and only then removes the read-only marker.
// If any of that fails, the marker stays, and OPF stays read-only.

// TakeOverFile, in the state directory, holds an import waiting for OPF to start again out of
// read-only mode.
const TakeOverFile = "takeover.json"

// importPfFile is where the import writes the pf.conf OPF would write,
// for pfctl to read.
const importPfFile = "import-pf.conf"

type takeOver struct {
	Model       *pf.Model `json:"model"`
	Overwrite   []string  `json:"overwrite"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
	By          string    `json:"by,omitempty"`
}

// OnTakeOver sets what's called after a read-only OPF has saved an
// import to take the machine over: cmd/opf starts OPF again without
// -readonly. Without it, read-only OPF can't take over.
func (m *Manager) OnTakeOver(f func()) { m.takeOverHook = f }

// Import reads the machine's configuration into a model, without
// changing anything: only for a machine OPF doesn't manage yet.
func (m *Manager) Import(req ImportRequest) (*ImportReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.canImport(); err != nil {
		return nil, err
	}
	r, _, err := m.importReport(req)
	return r, apiError(err)
}

func (m *Manager) canImport() error {
	_, live, err := m.live()
	if err != nil {
		return apiError(err)
	}
	if live != NoVersion {
		return errorf(CodeConflict, "OPF manages this machine already: its configuration is OPF's")
	}
	return nil
}

// importReport imports the machine, and plans the files OPF would write
// in place of its own. It returns the paths the first commit replaces.
func (m *Manager) importReport(req ImportRequest) (*ImportReport, []string, error) {
	src, err := m.importSources()
	if err != nil {
		return nil, nil, err
	}
	opts := pf.ImportOptions{Manage: req.Manage}
	res := pf.Import(src, opts)
	machinePf, pfErr := m.pfctlRuleset(m.store.SystemPath("/etc/pf.conf"))
	rep, overwrite, err := m.reportOn(res, src, machinePf, pfErr, false)
	if err != nil {
		return nil, nil, err
	}
	if rep.Ruleset != nil && rep.Ruleset.NoCatchAll {
		// None of the machine's rules matches every packet: written out
		// first, pf's own default keeps OPF's from deciding.
		opts.Pf.ExplicitDefault = true
		res = pf.Import(src, opts)
		if rep, overwrite, err = m.reportOn(res, src, machinePf, pfErr, true); err != nil {
			return nil, nil, err
		}
	}
	return rep, overwrite, nil
}

func (m *Manager) reportOn(res *pf.ImportResult, src pf.ImportSources, machinePf string, pfErr error, explicit bool) (*ImportReport, []string, error) {
	rep := &ImportReport{Model: res.Model, Notes: res.Notes, Areas: res.Areas, Files: []ImportFile{}, Problems: []Detail{}}
	if rep.Notes == nil {
		rep.Notes = []pf.ImportNote{}
	}
	for _, fe := range pf.Validate(res.Model) {
		rep.Problems = append(rep.Problems, Detail{Path: fe.Path, Message: fe.Message})
	}
	gen, err := m.planned(res.Model)
	var ae *Error
	if errors.As(err, &ae) {
		for _, d := range ae.Details {
			rep.Problems = append(rep.Problems, d)
		}
		gen = generated(res.Model)
	} else if err != nil {
		return nil, nil, err
	}

	// What the first commit would do to each file.
	var paths []string
	for p := range gen {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	sum := sha256.New()
	enc, err := EncodeModel(res.Model)
	if err != nil {
		return nil, nil, err
	}
	sum.Write(enc)
	var overwrite []string
	for _, p := range paths {
		f, err := m.store.LookupPath(p)
		if err != nil {
			return nil, nil, fmt.Errorf("the generator wrote %s, which isn't a managed file: %w", p, err)
		}
		disk, onDisk, err := m.store.Live(f.Name)
		if err != nil {
			return nil, nil, err
		}
		want := config.Normalize([]byte(gen[p]))
		fmt.Fprintf(sum, "\x00%s\x00%x\x00%x", p, sha256.Sum256(disk), sha256.Sum256(want))
		file := ImportFile{Path: p, Desc: f.Desc, Status: "same"}
		switch {
		case !onDisk:
			file.Status = "added"
		case !bytes.Equal(disk, want):
			file.Status = "changed"
			overwrite = append(overwrite, p)
		}
		if file.Status != "same" {
			old := string(disk)
			if !onDisk {
				old = ""
			}
			if d, err := config.Diff(old, string(want), p+" (now)", p+" (OPF's)"); err == nil {
				file.Diff = d
			}
		}
		rep.Files = append(rep.Files, file)
	}
	rep.Fingerprint = hex.EncodeToString(sum.Sum(nil))[:20]

	// The ruleset: pfctl reads both files.
	switch {
	case pfErr != nil:
		rep.RulesetError = pfErr.Error()
	default:
		path := m.store.StatePath(importPfFile)
		if err := os.WriteFile(path, config.Normalize([]byte(gen["/etc/pf.conf"])), 0600); err != nil {
			rep.RulesetError = "couldn't write OPF's pf.conf for pfctl to read: " + err.Error()
			break
		}
		defer os.Remove(path)
		opfPf, err := m.pfctlRuleset(path)
		if err != nil {
			rep.RulesetError = "pfctl doesn't load the pf.conf OPF would write: " + err.Error()
			rep.Problems = append(rep.Problems, Detail{Path: "/etc/pf.conf", Message: rep.RulesetError})
			break
		}
		rep.Ruleset = pf.ComparePfRulesets(machinePf, opfPf, explicit)
	}
	return rep, overwrite, nil
}

// pfctlRuleset is the ruleset pfctl reads from a pf.conf, without
// loading it (pfctl -nvf).
func (m *Manager) pfctlRuleset(path string) (string, error) {
	out, err := m.read("pfctl", "-nvf", path)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return out, nil
}

var ifconfigNameRE = regexp.MustCompile(`(?m)^([a-z]+[0-9]+): `)

// importSources reads what an import reads from the machine.
func (m *Manager) importSources() (pf.ImportSources, error) {
	src := pf.ImportSources{Files: map[string]string{}}
	paths := slices.Clone(pf.ImportPaths)
	matches, _ := filepath.Glob(m.store.SystemPath("/etc/hostname.*"))
	for _, p := range matches {
		paths = append(paths, "/etc/"+filepath.Base(p))
	}
	for _, p := range paths {
		data, err := os.ReadFile(m.store.SystemPath(p))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return src, fmt.Errorf("reading %s: %w", p, err)
		}
		src.Files[p] = string(data)
	}
	if out, err := m.read("ifconfig", "egress"); err == nil {
		for _, sub := range ifconfigNameRE.FindAllStringSubmatch(out, -1) {
			src.Egress = append(src.Egress, sub[1])
		}
	}
	return src, nil
}

// TakeOver stages the import of the machine's configuration as OPF's
// first change, if the import is still the one the admin saw
// (req.Fingerprint). Read-only, it's saved, and OPF starts again out of
// read-only mode to stage it.
func (m *Manager) TakeOver(req TakeOverRequest) (*TakeOverResult, error) {
	return m.TakeOverBy(req, "")
}

// TakeOverBy is TakeOver, saying who asked.
func (m *Manager) TakeOverBy(req TakeOverRequest, by string) (*TakeOverResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.canImport(); err != nil {
		return nil, err
	}
	rep, overwrite, err := m.importReport(req.ImportRequest)
	if err != nil {
		return nil, apiError(err)
	}
	switch {
	case req.Fingerprint != rep.Fingerprint:
		return nil, errorf(CodeConflict, "the machine's configuration changed since you looked at it; look again")
	case len(rep.Problems) > 0:
		e := errorf(CodeInvalid, "OPF can't take this configuration over as it is")
		e.Details = rep.Problems
		return nil, e
	case (rep.Ruleset == nil || !rep.Ruleset.Same) && !req.AcceptDifferences:
		return nil, errorf(CodeInvalid, "the pf.conf OPF would write doesn't load as the same ruleset; accept the differences to take over anyway")
	}
	if !m.ReadOnly() {
		st, err := m.stage(StageRequest{Base: NoVersion, Model: rep.Model, Overwrite: overwrite})
		if err != nil {
			return nil, apiError(err)
		}
		m.acceptTakeOver(overwrite)
		m.RecordEvent(Event{Time: time.Now(), Kind: EventCommit, Message: takeOverMessage(by)})
		return &TakeOverResult{Staged: st}, nil
	}
	if m.takeOverHook == nil {
		return nil, errorf(CodeUnsupported, "this OPF can't start itself again out of read-only mode; take it over on the machine instead")
	}
	data, err := json.Marshal(takeOver{Model: rep.Model, Overwrite: overwrite, Fingerprint: rep.Fingerprint, At: time.Now(), By: by})
	if err != nil {
		return nil, apiError(err)
	}
	path := m.store.StatePath(TakeOverFile)
	if err := os.WriteFile(path+".new", data, 0600); err != nil {
		return nil, apiError(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		return nil, apiError(err)
	}
	log.Printf("taking the machine over: starting again out of read-only mode to stage its configuration")
	go m.takeOverHook()
	return &TakeOverResult{Restarting: true}, nil
}

func takeOverMessage(by string) string {
	msg := "Imported this machine's configuration; it's staged as OPF's first change, to review and commit"
	if by != "" {
		msg = by + " imported this machine's configuration; it's staged as OPF's first change, to review and commit"
	}
	return msg
}

// TakeOverPending says whether an import waits in the state directory
// for OPF to start out of read-only mode.
func TakeOverPending(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, TakeOverFile))
	return err == nil
}

// ResumeTakeOver stages the import a read-only OPF saved before it
// started again (TakeOver). The file is gone afterwards, staged or not:
// a failure is logged and recorded, and taking over can be tried again.
func (m *Manager) ResumeTakeOver() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.store.StatePath(TakeOverFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	var t takeOver
	if err := json.Unmarshal(data, &t); err != nil || t.Model == nil {
		return fmt.Errorf("reading %s: %v", path, err)
	}
	if err := m.canImport(); err != nil {
		return err
	}
	if _, err := m.stage(StageRequest{Base: NoVersion, Model: t.Model, Overwrite: t.Overwrite}); err != nil {
		m.RecordEvent(Event{Time: time.Now(), Kind: EventCommit, Warning: true, Message: "Taking this machine over failed, so OPF is still only monitoring it: " + apiError(err).Error()})
		return err
	}
	m.acceptTakeOver(t.Overwrite)
	m.RecordEvent(Event{Time: time.Now(), Kind: EventCommit, Message: takeOverMessage(t.By)})
	return nil
}

// takeOverAccepted, in the state directory, is each file the admin
// agreed to replace when taking the machine over, with a hash of its
// contents then. Until the first commit, staging again (reviewing the
// import, or changing it first) may replace a file still as it was
// then without being told again; one changed since is changed outside
// OPF, as ever.
const takeOverAccepted = "takeover-accepted.json"

func (m *Manager) acceptTakeOver(paths []string) {
	acc := map[string]string{}
	for _, p := range paths {
		f, err := m.store.LookupPath(p)
		if err != nil {
			continue
		}
		if disk, ok, err := m.store.Live(f.Name); err == nil && ok {
			acc[p] = contentHash(disk)
		}
	}
	data, err := json.Marshal(acc)
	if err == nil {
		err = os.WriteFile(m.store.StatePath(takeOverAccepted), data, 0600)
	}
	if err != nil {
		log.Printf("taking over: recording the files you agreed to replace: %v", err)
	}
}

// acceptedAtTakeOver says whether the admin agreed, taking the machine
// over, to replace a file that's still as it was then: only before the
// first commit.
func (m *Manager) acceptedAtTakeOver(path string, disk []byte) bool {
	data, err := os.ReadFile(m.store.StatePath(takeOverAccepted))
	if err != nil {
		return false
	}
	var acc map[string]string
	if json.Unmarshal(data, &acc) != nil {
		return false
	}
	h, ok := acc[path]
	return ok && h == contentHash(disk)
}

func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
