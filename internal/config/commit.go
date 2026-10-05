package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"slices"
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
// Confirm is called. A commit with either those or ConfirmInstalled
// files waits for confirmation; if it isn't confirmed before the
// timeout the whole commit is reverted. If anything fails to apply, the whole commit is
// reverted and the staged changes are kept so they can be fixed.
func (s *Store) Commit(ctx context.Context, info CommitInfo) (*Entry, error) {
	e, err := s.commit(ctx, info)
	if err == nil && e.Status == StatusPending {
		if f := s.onPending.Load(); f != nil {
			(*f)(*e)
		}
	}
	return e, err
}

func (s *Store) commit(ctx context.Context, info CommitInfo) (*Entry, error) {
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
		if c.File.Check == nil || c.Removed {
			continue
		}
		out, err := s.checker().Run(ctx, subst(c.File.Check, s.candidatePath(c.File))...)
		if err != nil {
			return nil, &CheckError{File: c.File.Path, Output: string(out) + err.Error()}
		}
	}

	e := &Entry{ID: newID(time.Now()), Time: time.Now(), Status: StatusApplying, Message: info.Message, Author: info.Author, Changes: info.Changes}
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
		// A removed file has no new contents; its absence is the record.
		if !c.Removed {
			staged, _, err := s.staged(f)
			if err != nil {
				return nil, err
			}
			if err := writeFileAtomic(s.historyFile(e.ID, "new", f.Path), staged, 0600); err != nil {
				return nil, err
			}
			s.logFile("snapshot", f, s.historyFile(e.ID, "new", f.Path), "contents of commit "+e.ID)
		}
		e.Files = append(e.Files, EntryFile{Name: f.Name, Path: f.Path, Existed: existed, Removed: c.Removed, Confirm: f.Confirm, ConfirmInstalled: f.ConfirmInstalled})
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

	// What goes away is taken down before anything is brought up: a
	// default gateway given up for DHCP's has to be gone before the
	// interface asks for a lease, whose route goes through the same
	// router. Each service is told once, after the last of its files
	// changed here is in place (and before rc.conf.local, which comes
	// last and starts services it enables).
	order := takeDownFirst(len(e.Files), func(i int) bool { return e.Files[i].Removed })
	last := map[string]int{}
	for _, i := range order {
		if f, _ := s.Lookup(e.Files[i].Name); !e.Files[i].Confirm && f.Service != "" {
			last[f.Service] = i
		}
	}
	managed := s.managed(e)
	batch := newServiceBatch()
	for _, i := range order {
		ef := e.Files[i]
		if ef.Confirm {
			continue
		}
		f, _ := s.Lookup(ef.Name)
		if ef.Removed {
			if err := s.remove(ctx, f, s.historyFile(e.ID, "old", f.Path), "commit "+e.ID, &logBuf); err != nil {
				return fail(err)
			}
			batch.add(f, true)
		} else {
			staged, _, err := s.staged(f)
			if err != nil {
				return fail(err)
			}
			fmt.Fprintf(&logBuf, "# install %s\n", f.Path)
			if err := s.install(f, staged, "commit "+e.ID); err != nil {
				return fail(err)
			}
			if err := s.applyFile(ctx, f, s.livePath(f), &logBuf); err != nil {
				return fail(err)
			}
			batch.add(f, false)
		}
		if f.Service != "" && last[f.Service] == i && !managed[f.Service] {
			if err := s.tellService(ctx, batch, f.Service, &logBuf); err != nil {
				return fail(err)
			}
		}
	}
	for _, ef := range e.Files {
		if !ef.Confirm {
			continue
		}
		f, _ := s.Lookup(ef.Name)
		fmt.Fprintf(&logBuf, "# load %s from staged copy\n", f.Path)
		if err := s.applyFile(ctx, f, s.historyFile(e.ID, "new", f.Path), &logBuf); err != nil {
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
		if ef.NeedsConfirm() {
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
	// A copy: the confirm timeout may revert the entry meanwhile.
	out := *e
	out.Files = slices.Clone(e.Files)
	return &out, nil
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
func (s *Store) Confirm() error { return s.ConfirmBy("") }

// ConfirmBy is Confirm, saying in the commit's log who confirmed it.
func (s *Store) ConfirmBy(by string) error {
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
	if by != "" {
		e.Log += "\nConfirmed by " + by + ".\n" + logBuf.String()
	} else {
		e.Log += "\nConfirmed.\n" + logBuf.String()
	}
	return s.saveEntry(e)
}

// Revert undoes the pending commit now instead of waiting for the
// timeout. Its changes are staged again.
func (s *Store) Revert(ctx context.Context) error { return s.RevertBy(ctx, "") }

// RevertBy is Revert, saying in the commit's log who reverted it.
func (s *Store) RevertBy(ctx context.Context, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return ErrNoPending
	}
	s.pending.timer.Stop()
	if by == "" {
		by = "user"
	}
	return s.revertPending(ctx, "Reverted by "+by+".")
}

// RevertStopping undoes the pending commit because OPF is stopping, so
// nothing unconfirmed stays loaded after it.
func (s *Store) RevertStopping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return ErrNoPending
	}
	s.pending.timer.Stop()
	return s.revertPending(ctx, "OPF stopped before this commit was confirmed; reverted.")
}

func (s *Store) expire(p *pendingCommit) {
	if !s.expireLocked(p) {
		return
	}
	if f := s.expired.Load(); f != nil {
		(*f)()
	}
}

func (s *Store) expireLocked(p *pendingCommit) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != p {
		return false // confirmed or reverted in the meantime
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.revertPending(ctx, "Not confirmed in time; reverted."); err != nil {
		log.Printf("config: reverting %s: %v", p.entry.ID, err)
	}
	return true
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
	return s.recover(ctx, "OPF restarted before this commit finished; reverted.")
}

func (s *Store) recover(ctx context.Context, reason string) error {
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
		errs = append(errs, s.finishRevert(ctx, e, reason))
	}
	return errors.Join(errs...)
}

// revertEntry puts every file in e back the way it was and reloads it.
// It keeps going after errors so as much as possible is restored.
//
// Every file is back on disk before any is applied, and they're applied
// in the commit's order: what the commit created is taken down first,
// then interfaces before the default gateway (which may only be
// reachable through an interface's old address) and before pf.
func (s *Store) revertEntry(ctx context.Context, e *Entry, logBuf *bytes.Buffer) error {
	var errs []error
	type undo struct {
		f       File
		created bool // the commit created it; it's gone again
	}
	todo := make([]*undo, len(e.Files))
	for i := len(e.Files) - 1; i >= 0; i-- {
		ef := e.Files[i]
		f, err := s.Lookup(ef.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		live := s.livePath(f)
		switch {
		case ef.Confirm:
			// Never written; the live file is loaded again below.
		case ef.Existed:
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
		default:
			if err := os.Remove(live); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			} else {
				s.logFile("remove", f, live, "reverting commit "+e.ID+", didn't exist before")
			}
			fmt.Fprintf(logBuf, "# remove %s\n", f.Path)
			todo[i] = &undo{f: f, created: true}
			continue
		}
		todo[i] = &undo{f: f}
	}

	batch := newServiceBatch()
	for _, i := range takeDownFirst(len(todo), func(i int) bool { return todo[i] != nil && todo[i].created }) {
		u := todo[i]
		if u == nil {
			continue
		}
		f, live := u.f, s.livePath(u.f)
		if u.created {
			// Undo what the commit set up with it: an interface it
			// created is destroyed.
			if f.Remove != nil {
				if err := s.logRun(ctx, logBuf, subst(f.Remove, s.historyFile(e.ID, "new", f.Path))...); err != nil {
					errs = append(errs, err)
				}
			}
			if f.ApplyWhenRemoved {
				if err := s.applyFile(ctx, f, live, logBuf); err != nil {
					errs = append(errs, err)
				}
			}
			batch.add(f, true)
			continue
		}
		if _, err := os.Stat(live); err != nil {
			continue // nothing to reload
		}
		if err := s.applyFile(ctx, f, live, logBuf); err != nil {
			errs = append(errs, err)
		}
		batch.add(f, false)
	}
	// Services are told once, when every file is back.
	managed := s.managed(e)
	for _, svc := range batch.order {
		if managed[svc] {
			continue
		}
		if err := s.tellService(ctx, batch, svc, logBuf); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// takeDownFirst orders n files with those that go away (removed) first,
// each group in registry order.
func takeDownFirst(n int, removed func(int) bool) []int {
	var gone, rest []int
	for i := range n {
		if removed(i) {
			gone = append(gone, i)
		} else {
			rest = append(rest, i)
		}
	}
	return append(gone, rest...)
}

// managed is the services that a file of e brings in line itself when
// it's applied (File.Manages).
func (s *Store) managed(e *Entry) map[string]bool {
	out := map[string]bool{}
	for _, ef := range e.Files {
		if f, err := s.Lookup(ef.Name); err == nil {
			for _, svc := range f.Manages {
				out[svc] = true
			}
		}
	}
	return out
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
		if ef.Removed {
			errs = append(errs, s.stageRemoval(f))
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

// remove deletes a live file for a commit and undoes what it set up;
// removed is a copy of what the file held.
func (s *Store) remove(ctx context.Context, f File, removed, why string, logBuf *bytes.Buffer) error {
	if err := os.Remove(s.livePath(f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.logFile("remove", f, s.livePath(f), why)
	fmt.Fprintf(logBuf, "# remove %s\n", f.Path)
	if f.Remove != nil {
		return s.logRun(ctx, logBuf, subst(f.Remove, removed)...)
	}
	return nil
}

// apply activates f, loading it from path.
// applyFile runs a file's Apply command, if it has one; its service is
// told separately (tellService).
func (s *Store) applyFile(ctx context.Context, f File, path string, logBuf *bytes.Buffer) error {
	if f.Apply != nil {
		return s.logRun(ctx, logBuf, subst(f.Apply, path)...)
	}
	return nil
}

// serviceBatch collects the files of each service that a commit or a
// revert changed, so each service is told once.
type serviceBatch struct {
	order []string
	files map[string][]File
	full  map[string]bool // a file without ReloadWith, or removed, changed
	done  map[string]bool
}

func newServiceBatch() *serviceBatch {
	return &serviceBatch{files: map[string][]File{}, full: map[string]bool{}, done: map[string]bool{}}
}

func (b *serviceBatch) add(f File, removed bool) {
	if f.Service == "" {
		return
	}
	if _, ok := b.files[f.Service]; !ok {
		b.order = append(b.order, f.Service)
	}
	b.files[f.Service] = append(b.files[f.Service], f)
	if removed || f.ReloadWith == nil {
		b.full[f.Service] = true
	}
}

// tellService makes a running service take its changed files: with
// each one's ReloadWith when they all have one, else with the strongest
// ServiceAction among them (restart over reload).
func (s *Store) tellService(ctx context.Context, b *serviceBatch, svc string, logBuf *bytes.Buffer) error {
	if b.done[svc] {
		return nil
	}
	b.done[svc] = true
	files := b.files[svc]
	action := "reload"
	for _, f := range files {
		if f.ServiceAction == "restart" {
			action = "restart"
		}
	}
	if _, err := s.run.Run(ctx, "rcctl", "check", svc); err != nil {
		fmt.Fprintf(logBuf, "# %s is not running; not %sing\n", svc, action)
		return nil
	}
	if !b.full[svc] {
		for _, f := range files {
			if err := s.logRun(ctx, logBuf, subst(f.ReloadWith, s.livePath(f))...); err != nil {
				return err
			}
		}
		return nil
	}
	return s.logRun(ctx, logBuf, "rcctl", action, svc)
}

func (s *Store) logRun(ctx context.Context, logBuf *bytes.Buffer, argv ...string) error {
	fmt.Fprintf(logBuf, "$ %s\n", strings.Join(argv, " "))
	out, err := s.run.Run(ctx, argv...)
	logBuf.Write(out)
	return err
}
