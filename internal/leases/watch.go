package leases

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Interval is how often a Watcher checks the leases and the resolver.
// Checking the resolver is what notices unbound reloading, which
// forgets every record added at runtime.
const Interval = 15 * time.Second

// Watcher keeps the resolver's records in step with the leases file and
// the live model.
type Watcher struct {
	// File is the leases file to read.
	File string
	// Model returns the live model.
	Model    func() (*pf.Model, error)
	Resolver Resolver
	Log      *log.Logger
	Now      func() time.Time // time.Now if nil

	kick chan struct{}
	once sync.Once

	// What was last logged, to report changes rather than every pass.
	lastErr     string
	lastSkipped string
}

func (w *Watcher) init() {
	w.once.Do(func() { w.kick = make(chan struct{}, 1) })
}

// Kick asks for a pass now, for when the configuration has just
// changed (which may have reloaded unbound). It doesn't block.
func (w *Watcher) Kick() {
	w.init()
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Run syncs every Interval, and when kicked, until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	w.init()
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, time.Minute)
		w.report(w.Sync(pass))
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.kick:
		}
	}
}

func (w *Watcher) report(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != w.lastErr {
		if err != nil {
			w.logf("dns: registering DHCP leases: %v", err)
		} else if w.lastErr != "" {
			w.logf("dns: registering DHCP leases again")
		}
		w.lastErr = msg
	}
}

func (w *Watcher) logf(format string, args ...any) {
	if w.Log != nil {
		w.Log.Printf(format, args...)
	}
}

// Sync makes one pass. It does nothing while registration is turned
// off: unbound's control socket only exists while it's on, and turning
// it off reloads unbound, which drops the records.
func (w *Watcher) Sync(ctx context.Context) error {
	m, err := w.Model()
	if err != nil {
		return fmt.Errorf("reading the configuration: %w", err)
	}
	if m == nil || !Enabled(m) {
		return nil
	}
	now := time.Now()
	if w.Now != nil {
		now = w.Now()
	}
	leases, err := w.read()
	if err != nil {
		return err
	}
	want, skipped := Records(m, leases, now)
	w.reportSkipped(skipped)
	have, err := w.Resolver.List(ctx)
	if err != nil {
		return fmt.Errorf("reading unbound's local data: %w", err)
	}
	return w.reconcile(ctx, Zone(m), Static(m), want, have)
}

func (w *Watcher) read() ([]Lease, error) {
	f, err := os.Open(w.File)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // dhcpd hasn't run yet
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	leases, err := Parse(f)
	if err != nil {
		// Leave the records as they are until the file is readable.
		return nil, fmt.Errorf("%s: %w", w.File, err)
	}
	return leases, nil
}

// reconcile adds and removes records so that the names in zone that
// aren't the configuration's (static) are exactly want. Records in the
// zone that the configuration doesn't define are taken to be a lease's,
// so ones left from before a restart, or added by hand, are removed.
func (w *Watcher) reconcile(ctx context.Context, zone string, static map[string]bool, want, have []Record) error {
	wanted := map[string]netip.Addr{}
	for _, r := range want {
		wanted[r.Name] = r.IP
	}
	present := map[string][]netip.Addr{}
	for _, r := range have {
		if strings.HasSuffix(r.Name, "."+zone) && !static[r.Name] {
			present[r.Name] = append(present[r.Name], r.IP)
		}
	}

	var errs []error
	for _, name := range sortedKeys(present) {
		ips := present[name]
		if ip, ok := wanted[name]; ok && len(ips) == 1 && ips[0] == ip {
			delete(wanted, name) // already right
			continue
		}
		if err := w.Resolver.Remove(ctx, name); err != nil {
			errs = append(errs, err)
			delete(wanted, name) // don't add beside a stale record
			continue
		}
		if _, ok := wanted[name]; !ok {
			w.logf("dns: removed %s (lease ended)", strings.TrimSuffix(name, "."))
		}
	}
	for _, name := range sortedKeys(wanted) {
		r := Record{Name: name, IP: wanted[name]}
		if err := w.Resolver.Add(ctx, r); err != nil {
			errs = append(errs, err)
			continue
		}
		w.logf("dns: %s is %s (DHCP lease)", strings.TrimSuffix(name, "."), r.IP)
	}
	return errors.Join(errs...)
}

func (w *Watcher) reportSkipped(skipped []Skipped) {
	var b strings.Builder
	for _, s := range skipped {
		fmt.Fprintf(&b, "%s %q: %s; ", s.IP, s.Hostname, s.Reason)
	}
	if b.String() != w.lastSkipped {
		for _, s := range skipped {
			w.logf("dns: not registering %q for %s: %s", s.Hostname, s.IP, s.Reason)
		}
		w.lastSkipped = b.String()
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Memory is a Resolver that keeps records in memory and logs changes,
// for running without unbound (-dry, -mock).
type Memory struct {
	Log     *log.Logger
	mu      sync.Mutex
	records []Record
}

func (m *Memory) List(context.Context) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records), nil
}

func (m *Memory) Add(_ context.Context, r Record) error {
	if !ok(r.Name) {
		return fmt.Errorf("refusing to register %q", r.Name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, r)
	if m.Log != nil {
		m.Log.Printf("dry-run: unbound-control local_data %s %d IN A %s", r.Name, TTL, r.IP)
	}
	return nil
}

func (m *Memory) Remove(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = slices.DeleteFunc(m.records, func(r Record) bool { return r.Name == name })
	if m.Log != nil {
		m.Log.Printf("dry-run: unbound-control local_data_remove %s", name)
	}
	return nil
}
