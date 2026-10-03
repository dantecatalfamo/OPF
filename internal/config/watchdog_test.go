package config

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLock(t *testing.T) {
	dir := t.TempDir()
	a, err := Lock(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir, 0); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	// Waiting: it's taken once the holder lets go.
	go func() { time.Sleep(300 * time.Millisecond); a.Close() }()
	b, err := Lock(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("waiting for the lock: %v", err)
	}
	b.Close()
}

// killedDuringWait commits a pf change that waits for confirmation, and
// stops its timer as if OPF had been killed.
func killedDuringWait(t *testing.T) (*Store, *Entry, string) {
	t.Helper()
	s, _, root := newTestStore(t, time.Hour)
	stage(t, s, "pf", "block\n")
	stage(t, s, "ntpd", "servers time.example\n")
	e, err := s.Commit(context.Background(), CommitInfo{})
	if err != nil {
		t.Fatal(err)
	}
	s.pending.timer.Stop()
	return s, e, root
}

// The watchdog runs in a process of its own, with a store of its own.
func watchdogStore(t *testing.T, s *Store, root string) *Store {
	t.Helper()
	w, err := New(Options{Root: root, StateDir: s.dir, Files: testFiles, Runner: &fakeRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWatchdogRevertsWhenOPFIsGone(t *testing.T) {
	s, e, root := killedDuringWait(t)
	var slept time.Duration
	msg, err := watchdogStore(t, s, root).Watch(context.Background(), e.ID, func(d time.Duration) { slept = d })
	if err != nil {
		t.Fatal(err)
	}
	if slept < time.Hour || slept > time.Hour+WatchdogMargin {
		t.Errorf("slept %v, want the hour left plus the margin", slept)
	}
	if !strings.Contains(msg, "reverted") {
		t.Errorf("said %q", msg)
	}
	got, _ := s.Entry(e.ID)
	if got.Status != StatusReverted || !strings.Contains(got.Log, "watchdog") {
		t.Fatalf("status %s, log:\n%s", got.Status, got.Log)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers pool.ntp.org\n" {
		t.Fatalf("ntpd.conf not restored: %q", got)
	}
	// It doesn't keep the lock.
	l, err := Lock(s.dir, 0)
	if err != nil {
		t.Fatalf("lock after the watchdog: %v", err)
	}
	l.Close()
}

func TestWatchdogLeavesARunningOPFAlone(t *testing.T) {
	s, e, root := killedDuringWait(t)
	l, err := Lock(s.dir, 0) // OPF, alive
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	msg, err := watchdogStore(t, s, root).Watch(context.Background(), e.ID, func(time.Duration) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "running") {
		t.Errorf("said %q", msg)
	}
	if got, _ := s.Entry(e.ID); got.Status != StatusPending {
		t.Fatalf("status %s", got.Status)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers time.example\n" {
		t.Fatalf("ntpd.conf = %q", got)
	}
}

func TestWatchdogAfterConfirmation(t *testing.T) {
	// Confirmed before it starts: it doesn't wait.
	s, e, root := killedDuringWait(t)
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	msg, err := watchdogStore(t, s, root).Watch(context.Background(), e.ID, func(time.Duration) { t.Error("slept") })
	if err != nil || !strings.Contains(msg, "nothing to watch") {
		t.Fatalf("%q, %v", msg, err)
	}

	// Confirmed while it sleeps, by an OPF that has stopped since.
	s, e, root = killedDuringWait(t)
	msg, err = watchdogStore(t, s, root).Watch(context.Background(), e.ID, func(time.Duration) {
		if err := s.Confirm(); err != nil {
			t.Error(err)
		}
	})
	if err != nil || !strings.Contains(msg, "nothing to revert") {
		t.Fatalf("%q, %v", msg, err)
	}
	if got := readLive(t, root, "/etc/pf.conf"); got != "block\n" {
		t.Fatalf("pf.conf = %q", got)
	}
}

func TestOnPending(t *testing.T) {
	s, _, _ := newTestStore(t, time.Hour)
	var got []Entry
	s.OnPending(func(e Entry) { got = append(got, e) })
	stage(t, s, "ntpd", "servers time.example\n")
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("called for an applied commit: %+v", got)
	}
	stage(t, s, "pf", "block\n")
	e, err := s.Commit(context.Background(), CommitInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != e.ID || got[0].Deadline.IsZero() {
		t.Fatalf("got %+v", got)
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
}
