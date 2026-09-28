package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"
)

type pendingCommit struct {
	entry *Entry
	timer *time.Timer
}

// Commit validates and applies everything staged.
//
// Files without Confirm are installed and applied immediately. Confirm
// files are loaded from their staged copy and only installed once
// Confirm is called; if it isn't called before the timeout the whole
// commit is reverted. If anything fails to apply, the whole commit is
// reverted and the staged changes are kept so they can be fixed.
func (s *Store) Commit(ctx context.Context, info CommitInfo) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return nil, ErrPending
	}

	changes, err := s.Changes()
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, ErrNoChanges
	}
	var drifted []string
	for _, c := range changes {
		if c.Drifted {
			drifted = append(drifted, c.File.Path)
		}
	}
	if drifted != nil {
		return nil, &DriftError{Files: drifted}
	}
	for _, c := range changes {
		if c.File.Check == nil {
			continue
		}
		out, err := s.run.Run(ctx, subst(c.File.Check, s.candidatePath(c.File))...)
		if err != nil {
			return nil, &CheckError{File: c.File.Path, Output: string(out) + err.Error()}
		}
	}

	e := &Entry{ID: newID(time.Now()), Time: time.Now(), Status: StatusApplying, Message: info.Message, Changes: info.Changes}
	if _, err := os.Stat(s.historyDir(e.ID)); err == nil {
		return nil, fmt.Errorf("commit %s already exists; try again", e.ID)
	}
	for _, c := range changes {
		f := c.File
		old, existed, err := s.live(f)
		if err != nil {
			return nil, err
		}
		if existed {
			if err := writeFileAtomic(s.historyFile(e.ID, "old", f.Path), old, 0600); err != nil {
				return nil, err
			}
			s.logFile("snapshot", f, s.historyFile(e.ID, "old", f.Path), "restore point before commit "+e.ID)
		}
		staged, _, err := s.staged(f)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(s.historyFile(e.ID, "new", f.Path), staged, 0600); err != nil {
			return nil, err
		}
		s.logFile("snapshot", f, s.historyFile(e.ID, "new", f.Path), "contents of commit "+e.ID)
		e.Files = append(e.Files, EntryFile{Name: f.Name, Path: f.Path, Existed: existed, Confirm: f.Confirm})
	}
	// Written before anything live changes, so an interrupted commit
	// can be found and reverted by Recover.
	if err := s.saveEntry(e); err != nil {
		return nil, err
	}

	var logBuf bytes.Buffer
	fail := func(cause error) (*Entry, error) {
		fmt.Fprintf(&logBuf, "\nFailed: %v\nReverting.\n", cause)
		if err := s.revertEntry(ctx, e, &logBuf); err != nil {
			fmt.Fprintf(&logBuf, "Revert errors: %v\n", err)
		}
		e.Status = StatusFailed
		e.Log = logBuf.String()
		if err := s.saveEntry(e); err != nil {
			log.Printf("config: saving history %s: %v", e.ID, err)
		}
		return e, fmt.Errorf("commit failed and was reverted: %w", cause)
	}

	for _, ef := range e.Files {
		if ef.Confirm {
			continue
		}
		f, _ := s.Lookup(ef.Name)
		staged, _, err := s.staged(f)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(&logBuf, "# install %s\n", f.Path)
		if err := s.install(f, staged, "commit "+e.ID); err != nil {
			return fail(err)
		}
		if err := s.apply(ctx, f, s.livePath(f), &logBuf); err != nil {
			return fail(err)
		}
	}
	for _, ef := range e.Files {
		if !ef.Confirm {
			continue
		}
		f, _ := s.Lookup(ef.Name)
		fmt.Fprintf(&logBuf, "# load %s from staged copy\n", f.Path)
		if err := s.apply(ctx, f, s.historyFile(e.ID, "new", f.Path), &logBuf); err != nil {
			return fail(err)
		}
	}

	for _, c := range changes {
		s.logFile("clear", c.File, s.candidatePath(c.File), "used by commit "+e.ID)
		if err := s.discard(c.File); err != nil {
			log.Printf("config: clearing staged %s: %v", c.File.Name, err)
		}
	}

	e.Status = StatusApplied
	for _, ef := range e.Files {
		if ef.Confirm {
			e.Status = StatusPending
			e.Deadline = time.Now().Add(s.confirmTimeout)
			fmt.Fprintf(&logBuf, "\nWaiting for confirmation until %s.\n", e.Deadline.Format(time.TimeOnly))
			break
		}
	}
	e.Log = logBuf.String()
	if err := s.saveEntry(e); err != nil {
		log.Printf("config: saving history %s: %v", e.ID, err)
	}
	if e.Status == StatusPending {
		p := &pendingCommit{entry: e}
		p.timer = time.AfterFunc(s.confirmTimeout, func() { s.expire(p) })
		s.pending = p
	}
	return e, nil
}

// Pending returns the commit waiting for confirmation, if any.
func (s *Store) Pending() *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil
	}
	e := *s.pending.entry
	return &e
}

// Confirm installs the confirmable files of the pending commit.
func (s *Store) Confirm() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return ErrNoPending
	}
	e := s.pending.entry
	var logBuf strings.Builder
	for _, ef := range e.Files {
		if !ef.Confirm {
			continue
		}
		f, _ := s.Lookup(ef.Name)
		data, err := os.ReadFile(s.historyFile(e.ID, "new", f.Path))
		if err != nil {
			return err
		}
		// If this fails the timer keeps running and will revert.
		if err := s.install(f, data, "confirmed commit "+e.ID); err != nil {
			return err
		}
		fmt.Fprintf(&logBuf, "# install %s\n", f.Path)
	}
	s.pending.timer.Stop()
	s.pending = nil
	e.Status = StatusConfirmed
	e.Log += "\nConfirmed.\n" + logBuf.String()
	return s.saveEntry(e)
}

// Revert undoes the pending commit now instead of waiting for the
// timeout. Its changes are staged again.
func (s *Store) Revert(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return ErrNoPending
	}
	s.pending.timer.Stop()
	return s.revertPending(ctx, "Reverted by user.")
}

func (s *Store) expire(p *pendingCommit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != p {
		return // confirmed or reverted in the meantime
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.revertPending(ctx, "Not confirmed in time; reverted."); err != nil {
		log.Printf("config: reverting %s: %v", p.entry.ID, err)
	}
}

func (s *Store) revertPending(ctx context.Context, reason string) error {
	e := s.pending.entry
	s.pending = nil
	return s.finishRevert(ctx, e, reason)
}

func (s *Store) finishRevert(ctx context.Context, e *Entry, reason string) error {
	var logBuf bytes.Buffer
	fmt.Fprintf(&logBuf, "\n%s\n", reason)
	err := s.revertEntry(ctx, e, &logBuf)
	if err != nil {
		fmt.Fprintf(&logBuf, "Revert errors: %v\n", err)
	}
	if rerr := s.restage(e); rerr != nil {
		err = errors.Join(err, rerr)
	}
	e.Status = StatusReverted
	e.Deadline = time.Time{}
	e.Log += logBuf.String()
	return errors.Join(err, s.saveEntry(e))
}

// Recover reverts commits that were interrupted, or still waiting for
// confirmation, when OPF last stopped.
func (s *Store) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.History()
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.Status != StatusApplying && e.Status != StatusPending {
			continue
		}
		log.Printf("config: reverting unfinished commit %s", e.ID)
		errs = append(errs, s.finishRevert(ctx, e, "OPF restarted before this commit finished; reverted."))
	}
	return errors.Join(errs...)
}

// revertEntry puts every file in e back the way it was and reloads it.
// It keeps going after errors so as much as possible is restored.
func (s *Store) revertEntry(ctx context.Context, e *Entry, logBuf *bytes.Buffer) error {
	var errs []error
	for i := len(e.Files) - 1; i >= 0; i-- {
		ef := e.Files[i]
		f, err := s.Lookup(ef.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		live := s.livePath(f)
		if !ef.Confirm {
			if ef.Existed {
				old, err := os.ReadFile(s.historyFile(e.ID, "old", f.Path))
				if err == nil {
					err = writeFileAtomic(live, old, f.Mode)
				}
				if err != nil {
					errs = append(errs, err)
					continue
				}
				s.logFile("restore", f, live, "reverting commit "+e.ID)
				fmt.Fprintf(logBuf, "# restore %s\n", f.Path)
			} else {
				if err := os.Remove(live); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				} else {
					s.logFile("remove", f, live, "reverting commit "+e.ID+", didn't exist before")
				}
				fmt.Fprintf(logBuf, "# remove %s\n", f.Path)
				continue
			}
		}
		if _, err := os.Stat(live); err != nil {
			continue // nothing to reload
		}
		if err := s.apply(ctx, f, live, logBuf); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restage puts a reverted commit's contents back into the candidate so
// the user can fix them instead of starting over.
func (s *Store) restage(e *Entry) error {
	var errs []error
	for _, ef := range e.Files {
		f, err := s.Lookup(ef.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, staged, _ := s.staged(f); staged {
			continue
		}
		data, err := os.ReadFile(s.historyFile(e.ID, "new", f.Path))
		if err == nil {
			err = s.stage(f, data)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// apply activates f, loading it from path.
func (s *Store) apply(ctx context.Context, f File, path string, logBuf *bytes.Buffer) error {
	if f.Apply != nil {
		if err := s.logRun(ctx, logBuf, subst(f.Apply, path)...); err != nil {
			return err
		}
	}
	if f.Service != "" {
		if _, err := s.run.Run(ctx, "rcctl", "check", f.Service); err != nil {
			fmt.Fprintf(logBuf, "# %s is not running; not %sing\n", f.Service, f.ServiceAction)
			return nil
		}
		return s.logRun(ctx, logBuf, "rcctl", f.ServiceAction, f.Service)
	}
	return nil
}

func (s *Store) logRun(ctx context.Context, logBuf *bytes.Buffer, argv ...string) error {
	fmt.Fprintf(logBuf, "$ %s\n", strings.Join(argv, " "))
	out, err := s.run.Run(ctx, argv...)
	logBuf.Write(out)
	return err
}
