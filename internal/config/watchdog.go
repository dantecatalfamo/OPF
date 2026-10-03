package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockFile is the state directory's lock (see Lock).
const lockFile = "lock"

// ErrLocked means another process holds the state directory's lock.
var ErrLocked = errors.New("another OPF is running (it holds the state directory's lock)")

// Lock takes the state directory's lock. The running OPF holds it for as
// long as it runs: two OPFs never manage one system at once, and since
// the kernel lets go of a flock(2) lock when its holder dies, however it
// dies, the watchdog can tell whether OPF is still there. With wait, it
// keeps trying that long while another process holds it (a watchdog
// reverting, say); otherwise it fails straight away with ErrLocked.
//
// The file is opened close-on-exec, so processes OPF starts don't
// inherit the lock. Closing the file lets go of it.
func Lock(stateDir string, wait time.Duration) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, lockFile), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", f.Name(), err)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, ErrLocked
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// WatchdogMargin is how long after a commit's deadline the watchdog
// looks, which leaves a running OPF time to revert the commit itself.
const WatchdogMargin = 15 * time.Second

// Watch is the watchdog of a commit waiting for confirmation, run in a
// process of its own: if OPF is killed or crashes during the wait,
// nothing else would revert the commit until OPF started again. It
// sleeps until just after the deadline; then, if it can take the lock,
// OPF is gone, and it reverts what was left, as Recover does at start.
// If OPF holds the lock, OPF is alive and handles its own commits. It
// says what it did. sleep is time.Sleep but for tests.
func (s *Store) Watch(ctx context.Context, id string, sleep func(time.Duration)) (string, error) {
	e, err := s.Entry(id)
	if err != nil {
		return "", err
	}
	if e.Status != StatusPending {
		return fmt.Sprintf("commit %s is %s; nothing to watch", id, e.Status), nil
	}
	// A duration, which time.Sleep measures on the monotonic clock: the
	// wall clock being set meanwhile can't make it wake early or late.
	sleep(time.Until(e.Deadline) + WatchdogMargin)

	lock, err := Lock(s.dir, 0)
	if errors.Is(err, ErrLocked) {
		return "OPF is running; it handles its own commits", nil
	}
	if err != nil {
		return "", err
	}
	defer lock.Close()
	// Read again only now: under the lock no OPF is writing it.
	if e, err = s.Entry(id); err != nil {
		return "", err
	}
	if e.Status != StatusPending && e.Status != StatusApplying {
		return fmt.Sprintf("commit %s is %s; nothing to revert", id, e.Status), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute) // from now, not from before the sleep
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.recover(ctx, "OPF stopped without reverting this commit (it was killed or crashed); its watchdog reverted it."); err != nil {
		return "", err
	}
	return fmt.Sprintf("OPF is gone and commit %s wasn't confirmed; reverted it", id), nil
}
