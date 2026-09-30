package appliance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// pf's own state, read with pfctl and tcpdump. Rules are matched to the
// model by their labels (pf.Label), never by number or text: numbers
// change with every reload, and only labels reach the kernel.

// Limits on what the pf calls return, whatever the kernel holds, so an
// answer always fits in one RPC message.
const (
	MaxStates     = 5000
	MaxLogEntries = 500
)

// pflogPath is where pflogd writes logged packets.
const pflogPath = "/var/log/pflog"

// PfStatus returns whether pf is running, its state table, and traffic
// on the statistics interface.
func (m *Manager) PfStatus() (*PfStatus, error) {
	res := &PfStatus{Errors: []string{}}
	then, now, dt, err := m.pfInfo.sample(func() (sysinfo.PfInfo, error) {
		out, err := m.read("pfctl", "-v", "-s", "info")
		info, ok := sysinfo.ParsePfInfo(out)
		if !ok {
			if err == nil {
				err = fmt.Errorf("unexpected output")
			}
			return info, err
		}
		return info, nil
	})
	if err != nil {
		res.Errors = append(res.Errors, "couldn't read pf's status (pfctl -s info)")
		return res, nil
	}
	res.Info = &now
	if out, err := m.read("pfctl", "-s", "memory"); err == nil {
		if n, ok := sysinfo.ParsePfMemory(out)["states"]; ok {
			res.StateLimit = n
		}
	}
	// Blocked packets per second on the statistics interface, when it
	// was the same interface both times and the counters didn't reset.
	if a, b := then.Iface, now.Iface; a != nil && b != nil && a.Name == b.Name && dt > 0 {
		before := a.PacketsInBlocked + a.PacketsOutBlocked
		after := b.PacketsInBlocked + b.PacketsOutBlocked
		if after >= before {
			r := float64(after-before) / dt.Seconds()
			res.BlockedPerSec = &r
		}
	}
	return res, nil
}

// PfStates returns the state table, each state with the label of the
// rule that created it.
func (m *Manager) PfStates() (*PfStates, error) {
	res := &PfStates{States: []PfStateEntry{}}
	out, err := m.read("pfctl", "-vv", "-s", "states")
	if err != nil && out == "" {
		res.Error = "couldn't read the state table (pfctl -s states)"
		return res, nil
	}
	states, truncated := sysinfo.ParsePfStates(out, MaxStates)
	res.Truncated = truncated
	labels := m.ruleLabels()
	for _, s := range states {
		res.States = append(res.States, PfStateEntry{PfState: s, Label: labels[s.Rule]})
	}
	return res, nil
}

// ruleLabels maps the loaded rules' numbers to their labels.
func (m *Manager) ruleLabels() map[int]string {
	out, err := m.read("pfctl", "-vv", "-s", "rules")
	labels := map[int]string{}
	if err != nil {
		return labels
	}
	for _, r := range sysinfo.ParsePfRules(out) {
		if r.Label != "" {
			labels[r.Number] = r.Label
		}
	}
	return labels
}

// KillState ends one connection by its state id, as pfctl -vv -s
// states printed it.
func (m *Manager) KillState(req KillStateRequest) error {
	if !isHex(req.ID, 16) || !isHex(req.CreatorID, 8) {
		return errorf(CodeInvalid, "a state id is 16 hex digits and a creator id 8")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	out, err := m.runner().Run(ctx, "pfctl", "-k", "id", "-k", req.ID+"/"+req.CreatorID)
	if err != nil {
		return errorf(CodeInternal, "pfctl couldn't end the connection: %s", firstLine(string(out)))
	}
	// "killed 1 states" or "killed 0 states": a state that has already
	// gone is fine, the connection has ended either way.
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// RuleCounters returns the loaded rules' counters by label, added up
// over the rules pf expanded each labelled rule into.
func (m *Manager) RuleCounters() (*RuleCounters, error) {
	res := &RuleCounters{Labels: map[string]RuleCounter{}}
	out, err := m.read("pfctl", "-vv", "-s", "rules")
	if err != nil && out == "" {
		res.Error = "couldn't read the rules' counters (pfctl -s rules)"
		return res, nil
	}
	for _, r := range sysinfo.ParsePfRules(out) {
		if _, _, ok := pf.ParseLabel(r.Label); !ok {
			continue
		}
		c := res.Labels[r.Label]
		// Every expansion is evaluated for the packets that reach the
		// first; the most any of them was is how often the rule was.
		c.Evaluations = max(c.Evaluations, r.Evaluations)
		c.Packets += r.Packets
		c.Bytes += r.Bytes
		c.States += r.States
		res.Labels[r.Label] = c
	}
	return res, nil
}

// FirewallLog returns the latest packets pf logged, each with the label
// of the rule that logged it when that can be known: pflog records the
// rule's number, which only means the same rule until the ruleset is
// reloaded, so entries from before the last change get none.
func (m *Manager) FirewallLog() (*FirewallLog, error) {
	res := &FirewallLog{Entries: []FirewallLogEntry{}}
	out, err := m.read("tcpdump", "-n", "-e", "-ttt", "-r", pflogPath)
	now := time.Now()
	entries := sysinfo.ParsePflog(out, now, MaxLogEntries)
	if err != nil && len(entries) == 0 {
		// An empty or missing log (nothing logged yet) isn't an error.
		if !strings.Contains(out, "No such file") && strings.TrimSpace(out) != "" {
			res.Error = "couldn't read the firewall log: " + firstLine(out)
		}
		return res, nil
	}
	loaded := m.rulesetLoadedAfter()
	res.RulesSince = loaded
	labels := m.ruleLabels()
	// Newest first.
	for i := len(entries) - 1; i >= 0; i-- {
		e := FirewallLogEntry{PfLogEntry: entries[i]}
		if e.Anchor == "" && (loaded == nil || e.Time.After(*loaded)) {
			e.Label = labels[e.Rule]
		}
		res.Entries = append(res.Entries, e)
	}
	return res, nil
}

// rulesetLoadedAfter is the latest time the loaded ruleset can have
// changed through OPF: the newest commit, or for one that was reverted
// or failed, when putting the old ruleset back can have finished. nil
// when there's no history. (A ruleset loaded by hand isn't known.)
func (m *Manager) rulesetLoadedAfter() *time.Time {
	if m.store == nil {
		return nil
	}
	entries, err := m.store.History()
	if err != nil || len(entries) == 0 {
		return nil
	}
	var t time.Time
	for _, e := range entries {
		at := e.Time
		switch e.Status {
		case config.StatusReverted:
			if e.Deadline.After(at) {
				at = e.Deadline
			}
		case config.StatusFailed, config.StatusApplying:
			at = at.Add(commandTimeout)
		}
		if at.After(t) {
			t = at
		}
	}
	return &t
}
