// Package config stages, validates, commits and reverts changes to the
// system's configuration files.
//
// Layout of the state directory:
//
//	candidate/<path>        staged file contents, mirroring the live path
//	candidate/base.json     hash of the live file each candidate was based on
//	history/<id>/           one directory per commit (see history.go)
//	tmp/                    scratch files for ad-hoc checks
package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/dantecatalfamo/OPF/internal/run"
)

var (
	ErrUnknownFile = errors.New("unknown file")
	ErrPending     = errors.New("a commit is waiting for confirmation; confirm or revert it first")
	ErrNoPending   = errors.New("no commit is waiting for confirmation")
	ErrNoChanges   = errors.New("nothing is staged")
)

// DriftError means a live file changed after it was staged, e.g. it was
// edited by hand over SSH. Committing would silently discard that edit.
type DriftError struct{ Files []string }

func (e *DriftError) Error() string {
	return fmt.Sprintf("changed on disk since staging: %v; discard and re-stage", e.Files)
}

// CheckError means a staged file failed validation.
type CheckError struct {
	File   string
	Output string
}

func (e *CheckError) Error() string { return e.File + " failed its check" }

type Store struct {
	root           string // prefix for live paths; "" in production
	dir            string
	files          []File
	run            run.Runner
	confirmTimeout time.Duration

	mu      sync.Mutex
	pending *pendingCommit
}

type Options struct {
	Root           string
	StateDir       string
	Files          []File
	Runner         run.Runner
	ConfirmTimeout time.Duration
}

func New(opts Options) (*Store, error) {
	if err := validateFiles(opts.Files); err != nil {
		return nil, err
	}
	if opts.ConfirmTimeout <= 0 {
		opts.ConfirmTimeout = 60 * time.Second
	}
	s := &Store{
		root:           opts.Root,
		dir:            opts.StateDir,
		files:          opts.Files,
		run:            opts.Runner,
		confirmTimeout: opts.ConfirmTimeout,
	}
	for _, d := range []string{"candidate", "history", "tmp"} {
		if err := os.MkdirAll(filepath.Join(s.dir, d), 0700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Files lists the registry. Pattern entries (hostname.*) are listed as
// patterns; Lookup resolves their instances.
func (s *Store) Files() []File { return s.files }

// Lookup finds a managed file by name: a fixed entry, or an instance of
// a pattern entry such as hostname.em0 for hostname.*.
func (s *Store) Lookup(name string) (File, error) {
	for _, f := range s.files {
		if !f.isPattern() && f.Name == name {
			return f, nil
		}
	}
	for _, f := range s.files {
		if f.isPattern() {
			if g, ok := f.match(name); ok {
				return g, nil
			}
		}
	}
	return File{}, fmt.Errorf("%w: %s", ErrUnknownFile, name)
}

// instances returns the registry in apply order with each pattern entry
// replaced by its staged instances, sorted by name. Staged files are
// the ones with a base hash recorded.
func (s *Store) instances() ([]File, error) {
	bases, err := s.bases()
	if err != nil {
		return nil, err
	}
	var out []File
	for _, f := range s.files {
		if !f.isPattern() {
			out = append(out, f)
			continue
		}
		var names []string
		for name := range bases {
			if _, ok := f.match(name); ok {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		for _, name := range names {
			g, _ := f.match(name)
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *Store) livePath(f File) string      { return filepath.Join(s.root, f.Path) }
func (s *Store) candidatePath(f File) string { return filepath.Join(s.dir, "candidate", f.Path) }
func (s *Store) basePath() string            { return filepath.Join(s.dir, "candidate", "base.json") }

// Live returns the file as it is on the system. A missing file is not
// an error; exists reports whether it was there.
func (s *Store) Live(name string) (data []byte, exists bool, err error) {
	f, err := s.Lookup(name)
	if err != nil {
		return nil, false, err
	}
	return s.live(f)
}

func (s *Store) live(f File) ([]byte, bool, error) { return readOptional(s.livePath(f)) }

// Staged returns the staged contents of a file, if any.
func (s *Store) Staged(name string) (data []byte, staged bool, err error) {
	f, err := s.Lookup(name)
	if err != nil {
		return nil, false, err
	}
	return s.staged(f)
}

func (s *Store) staged(f File) ([]byte, bool, error) { return readOptional(s.candidatePath(f)) }

// Current returns the staged contents if there are any, else the live
// contents. This is what an editor should show.
func (s *Store) Current(name string) ([]byte, error) {
	f, err := s.Lookup(name)
	if err != nil {
		return nil, err
	}
	data, staged, err := s.staged(f)
	if err != nil || staged {
		return data, err
	}
	data, _, err = s.live(f)
	return data, err
}

// Stage records new contents for a file without touching the live
// file. Staging contents identical to the live file unstages it.
func (s *Store) Stage(name string, data []byte) error {
	f, err := s.Lookup(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return ErrPending
	}
	return s.stage(f, normalize(data))
}

func (s *Store) stage(f File, data []byte) error {
	live, _, err := s.live(f)
	if err != nil {
		return err
	}
	if bytes.Equal(live, data) {
		return s.discard(f)
	}
	bases, err := s.bases()
	if err != nil {
		return err
	}
	if _, ok := bases[f.Name]; !ok {
		bases[f.Name] = hash(s.livePath(f))
		if err := s.writeBases(bases); err != nil {
			return err
		}
	}
	return writeFileAtomic(s.candidatePath(f), data, 0600)
}

func (s *Store) Discard(name string) error {
	f, err := s.Lookup(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discard(f)
}

func (s *Store) discard(f File) error {
	if err := os.Remove(s.candidatePath(f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	bases, err := s.bases()
	if err != nil {
		return err
	}
	delete(bases, f.Name)
	return s.writeBases(bases)
}

func (s *Store) DiscardAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.instances()
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := s.discard(f); err != nil {
			return err
		}
	}
	return nil
}

// Change is a staged file compared against the live system.
type Change struct {
	File    File
	Diff    string
	Drifted bool // the live file changed after staging
}

// Changes lists staged files in apply order.
func (s *Store) Changes() ([]Change, error) {
	bases, err := s.bases()
	if err != nil {
		return nil, err
	}
	files, err := s.instances()
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, f := range files {
		if _, staged, err := s.staged(f); err != nil {
			return nil, err
		} else if !staged {
			continue
		}
		diff, err := Diff(s.livePath(f), s.candidatePath(f), f.Path+" (live)", f.Path+" (staged)")
		if err != nil {
			return nil, err
		}
		out = append(out, Change{
			File:    f,
			Diff:    diff,
			Drifted: bases[f.Name] != hash(s.livePath(f)),
		})
	}
	return out, nil
}

// CheckContent runs f's checker against arbitrary contents without
// staging them. ok is false if the check failed; err is only set if the
// check couldn't be run at all.
func (s *Store) CheckContent(ctx context.Context, name string, data []byte) (output string, ok bool, err error) {
	f, err := s.Lookup(name)
	if err != nil {
		return "", false, err
	}
	if f.Check == nil {
		return "No checker is available for this file.", true, nil
	}
	tmp, err := os.CreateTemp(filepath.Join(s.dir, "tmp"), f.Name+".*")
	if err != nil {
		return "", false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(normalize(data)); err != nil {
		tmp.Close()
		return "", false, err
	}
	if err := tmp.Close(); err != nil {
		return "", false, err
	}
	out, err := s.run.Run(ctx, subst(f.Check, tmp.Name())...)
	return string(out), err == nil, nil
}

func (s *Store) bases() (map[string]string, error) {
	m := map[string]string{}
	data, exists, err := readOptional(s.basePath())
	if err != nil || !exists {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

func (s *Store) writeBases(m map[string]string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.basePath(), data, 0600)
}

// Diff returns a unified diff between two files, either of which may be
// missing. It uses the system's diff(1).
func Diff(a, b, labelA, labelB string) (string, error) {
	for _, p := range []*string{&a, &b} {
		if _, err := os.Stat(*p); errors.Is(err, fs.ErrNotExist) {
			*p = os.DevNull
		}
	}
	out, err := exec.Command("diff", "-u", "-L", labelA, "-L", labelB, a, b).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		err = nil // files differ
	}
	return string(out), err
}

// normalize converts browser line endings and ensures a trailing
// newline, which many of the base system parsers expect.
func normalize(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return data
}

func hash(path string) string {
	data, exists, err := readOptional(path)
	if err != nil || !exists {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readOptional(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
}

// writeFileAtomic writes data next to path and renames it into place.
// An existing file's mode and ownership are preserved; otherwise mode
// is used.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	uid, gid := -1, -1
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".opf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if uid != -1 && os.Geteuid() == 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
