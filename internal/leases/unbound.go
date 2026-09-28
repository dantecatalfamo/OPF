package leases

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/run"
)

// Resolver is the resolver's runtime local data.
type Resolver interface {
	// List returns every A record in the local data.
	List(ctx context.Context) ([]Record, error)
	Add(ctx context.Context, r Record) error
	// Remove removes every record for a name.
	Remove(ctx context.Context, name string) error
}

// Unbound changes a running unbound's local data with unbound-control.
// The changes last until unbound reloads its configuration.
type Unbound struct {
	Runner run.Runner
	// Config is unbound.conf, which unbound-control reads to find the
	// control socket.
	Config string
}

func (u Unbound) control(ctx context.Context, args ...string) ([]byte, error) {
	return u.Runner.Run(ctx, append([]string{"unbound-control", "-c", u.Config}, args...)...)
}

func (u Unbound) List(ctx context.Context) ([]Record, error) {
	out, err := u.control(ctx, "list_local_data")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return parseLocalData(out), nil
}

// parseLocalData reads list_local_data's output, one record per line in
// presentation format: "name.<TAB>ttl<TAB>IN<TAB>A<TAB>address".
func parseLocalData(out []byte) []Record {
	var records []Record
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 5 || f[2] != "IN" || f[3] != "A" {
			continue
		}
		if _, err := strconv.ParseUint(f[1], 10, 32); err != nil {
			continue
		}
		ip, err := netip.ParseAddr(f[4])
		if err != nil {
			continue
		}
		records = append(records, Record{Name: strings.ToLower(f[0]), IP: ip})
	}
	return records
}

// Add's and Remove's arguments are joined with spaces and parsed by
// unbound as a record, so the name must be one Records produced: a
// validated label under the model's validated domain. ok checks again.

func (u Unbound) Add(ctx context.Context, r Record) error {
	if !ok(r.Name) || !r.IP.Is4() {
		return fmt.Errorf("refusing to register %q", r.Name)
	}
	return u.expectOK(ctx, "local_data", r.Name, strconv.Itoa(TTL), "IN", "A", r.IP.String())
}

func (u Unbound) Remove(ctx context.Context, name string) error {
	if !ok(name) {
		return fmt.Errorf("refusing to remove %q", name)
	}
	return u.expectOK(ctx, "local_data_remove", name)
}

func (u Unbound) expectOK(ctx context.Context, args ...string) error {
	out, err := u.control(ctx, args...)
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	if s := string(bytes.TrimSpace(out)); s != "ok" {
		return fmt.Errorf("unbound-control %s: %s", args[0], s)
	}
	return nil
}

// ok reports whether name is a fully qualified name made of valid
// labels.
func ok(name string) bool {
	if !strings.HasSuffix(name, ".") || len(name) > 254 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}
