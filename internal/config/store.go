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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	// ErrUnknownCommit means no commit has the id, or the id is malformed.
	ErrUnknownCommit = errors.New("no such commit")
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
	fileLog        *log.Logger

	mu      sync.Mutex
	pending *pendingCommit
}

type Options struct {
	Root           string
	StateDir       string
	Files          []File
	Runner         run.Runner
	ConfirmTimeout time.Duration
	// FileLog, when set, reports every change to a staged or live file:
	// the path on the real system, where it went (with Root, a scratch
	// location), and why. The mock server sets it.
	FileLog *log.Logger
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
		fileLog:        opts.FileLog,
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

// LookupPath finds a managed file by its path on the system, e.g.
// /etc/hostname.em0.
func (s *Store) LookupPath(path string) (File, error) {
	for _, f := range s.files {
		if !f.isPattern() && f.Path == path {
			return f, nil
		}
	}
	for _, f := range s.files {
		if !f.isPattern() {
			continue
		}
		prefix, suffix, _ := strings.Cut(f.Path, "*")
		if len(path) > len(prefix)+len(suffix) && strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) {
			if g, ok := f.instance(path[len(prefix) : len(path)-len(suffix)]); ok {
				return g, nil
			}
		}
	}
	return File{}, fmt.Errorf("%w: %s", ErrUnknownFile, path)
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
	live, exists, err := s.live(f)
	if err != nil {
		return err
	}
	if bytes.Equal(live, data) {
		return s.unstage(f, "same as the live file")
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
	if err := writeFileAtomic(s.candidatePath(f), data, 0600); err != nil {
		return err
	}
	note := ""
	if !exists {
		note = "new file"
	}
	s.logFile("stage", f, s.candidatePath(f), note)
	return nil
}

func (s *Store) Discard(name string) error {
	f, err := s.Lookup(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unstage(f, "discarded")
}

// unstage discards f's staged copy and reports it if there was one.
func (s *Store) unstage(f File, why string) error {
	_, staged, err := s.staged(f)
	if err != nil {
		return err
	}
	if err := s.discard(f); err != nil {
		return err
	}
	if staged {
		s.logFile("unstage", f, s.candidatePath(f), why)
	}
	return nil
}

// discard forgets f's staged copy, silently: also used to clear the
// candidate once a commit has used it.
func (s *Store) discard(f File) error {
	if err := os.Remove(s.candidatePath(f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	bases, err := s.bases()
	if err != nil {
		return err
	}
	if _, ok := bases[f.Name]; !ok {
		return nil // wasn't staged; leave the index alone
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
		if err := s.unstage(f, "discarded"); err != nil {
			return err
		}
	}
	return nil
}

// logFile reports an operation on a managed file to the FileLog, if
// there is one: its path on the real system, then where it went.
func (s *Store) logFile(op string, f File, path, note string) {
	s.logPath(op, f.Path, path, note)
}

// logPath reports a file operation. real is the path on the real system
// the file stands for, or "" for OPF's own bookkeeping files.
func (s *Store) logPath(op, real, path, note string) {
	if s.fileLog == nil {
		return
	}
	msg := fmt.Sprintf("file: %-8s ", op)
	switch {
	case real == "":
		msg += path
	case path == real:
		msg += real
	default:
		msg += real + " -> " + path
	}
	if note != "" {
		msg += " (" + note + ")"
	}
	s.fileLog.Print(msg)
}

// install writes a live file and reports it.
func (s *Store) install(f File, data []byte, why string) error {
	_, exists, err := s.live(f)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.livePath(f), data, f.Mode); err != nil {
		return err
	}
	note := why
	if !exists {
		note = fmt.Sprintf("%s, new file, mode %04o", why, f.Mode)
	}
	s.logFile("install", f, s.livePath(f), note)
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
	s.logFile("check", f, tmp.Name(), "temporary copy for the checker, removed after")
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
	if err := writeFileAtomic(s.basePath(), data, 0600); err != nil {
		return err
	}
	s.logPath("index", "", s.basePath(), fmt.Sprintf("staging index, %d staged", len(m)))
	return nil
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

// Normalize is how staged contents are stored: browser line endings
// converted and a trailing newline added, which many of the base system
// parsers expect. Compare against it to know what staging would write.
func Normalize(data []byte) []byte { return normalize(data) }

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
