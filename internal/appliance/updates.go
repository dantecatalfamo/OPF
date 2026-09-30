package appliance

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// Security patches, from syspatch -c. It fetches the list from a mirror
// and checks every patch, which takes a while, longer the more there
// are, so nothing waits on it: a checker runs it on a schedule in the
// background, keeps the answer in the state directory so a restart
// shows it at once, and Updates reports the last answer.

const (
	// UpdatesEvery is how often the checker asks, and updatesRetry how
	// soon after a failed check (no network yet, say).
	UpdatesEvery  = 2 * time.Hour
	updatesRetry  = 15 * time.Minute
	updatesLimit  = 10 * time.Minute // how long one check may take
	updatesMinGap = time.Minute      // CheckUpdates asked again sooner does nothing
	updatesFile   = "updates.json"
)

// Updates reports the last check's answer, and whether one is running.
func (m *Manager) Updates() (*UpdatesStatus, error) {
	m.updMu.Lock()
	defer m.updMu.Unlock()
	if m.upd == nil {
		return &UpdatesStatus{Checking: true, Patches: []string{}}, nil
	}
	u := *m.upd
	u.Checking = m.updRunning
	return &u, nil
}

// CheckUpdates starts a check now, unless one is running or the last
// finished less than a minute ago, and reports as Updates does.
func (m *Manager) CheckUpdates() (*UpdatesStatus, error) {
	m.startUpdateCheck(func(u *UpdatesStatus) bool {
		return u == nil || u.CheckedAt == nil || time.Since(*u.CheckedAt) >= updatesMinGap
	})
	return m.Updates()
}

// updatesDue says whether the schedule wants a check.
func updatesDue(u *UpdatesStatus) bool {
	if u == nil || u.CheckedAt == nil {
		return true
	}
	every := UpdatesEvery
	if u.Error != "" {
		every = updatesRetry
	}
	return time.Since(*u.CheckedAt) >= every
}

// startUpdateCheck runs a check in the background if none is running
// and due says one is wanted.
func (m *Manager) startUpdateCheck(due func(*UpdatesStatus) bool) {
	m.updMu.Lock()
	defer m.updMu.Unlock()
	if m.updRunning || !due(m.upd) {
		return
	}
	m.updRunning = true
	go m.checkUpdates()
}

func (m *Manager) checkUpdates() {
	ctx, cancel := context.WithTimeout(context.Background(), updatesLimit)
	defer cancel()
	out, err := m.runner().Run(ctx, "syspatch", "-c")
	now := time.Now()
	u := &UpdatesStatus{CheckedAt: &now, Patches: []string{}}
	if err != nil {
		u.Error = "couldn't check for patches: " + firstLine(string(out))
	} else {
		u.Patches = sysinfo.ParseSyspatch(string(out))
	}
	m.updMu.Lock()
	before := m.upd
	m.upd, m.updRunning = u, false
	m.updMu.Unlock()
	m.notePatches(before, u)
	if err := m.saveUpdates(u); err != nil {
		log.Printf("saving the patch check: %v", err)
	}
}

// RunUpdateChecker checks for patches when OPF starts, if the saved
// answer is stale, and then on the schedule, until ctx is done.
func (m *Manager) RunUpdateChecker(ctx context.Context) {
	m.loadUpdates()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		m.startUpdateCheck(updatesDue)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// The saved answer: the state directory's updates.json, written whole
// or not at all.

func (m *Manager) saveUpdates(u *UpdatesStatus) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	path := m.store.StatePath(updatesFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+updatesFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadUpdates reads the saved answer, if there's one and it's sound.
// It's cleaned as a fresh answer is (patch names are syspatch's, but
// the file could be anything).
func (m *Manager) loadUpdates() {
	data, err := os.ReadFile(m.store.StatePath(updatesFile))
	if err != nil || len(data) > 1<<20 {
		return
	}
	var u UpdatesStatus
	if json.Unmarshal(data, &u) != nil || u.CheckedAt == nil || u.CheckedAt.After(time.Now().Add(time.Minute)) {
		return
	}
	clean := []string{}
	for _, p := range u.Patches {
		if sysinfo.IsPatchName(p) {
			clean = append(clean, p)
		}
	}
	u.Patches, u.Checking = clean, false
	u.Error = printable(u.Error, maxMessageRunes)
	m.updMu.Lock()
	if m.upd == nil {
		m.upd = &u
	}
	m.updMu.Unlock()
}
