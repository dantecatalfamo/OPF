package appliance

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Looking a host name up as the firewall itself does: getent(1) asks
// the C library, which reads /etc/hosts and the servers in
// /etc/resolv.conf in the order its lookup line gives, as ifconfig does
// when netstart sets a WireGuard peer's wgendpoint. The UI asks while a
// peer's name is entered: a name that doesn't resolve makes netstart
// wait for it on every commit, and the tunnel never connects.

// HostLookupRequest is a host name to look up.
type HostLookupRequest struct {
	Name string `json:"name"`
}

// HostLookupResult is the name's addresses (none: no such name), or
// Error when the lookup didn't finish.
type HostLookupResult struct {
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
	// Seconds is how long the lookup took, which netstart waits too.
	Seconds float64 `json:"seconds"`
}

// hostLookupTimeout bounds a lookup; a name that takes longer holds up
// netstart as long. A variable for the tests.
var hostLookupTimeout = 8 * time.Second

// LookupHost looks a host name up with the firewall's own resolver
// configuration.
func (m *Manager) LookupHost(req HostLookupRequest) (*HostLookupResult, error) {
	name := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(req.Name)), ".")
	if _, err := netip.ParseAddr(name); err == nil || !isDNSName(name) || strings.HasPrefix(name, "-") {
		return nil, &Error{Code: CodeInvalid, Message: "enter a host name like vpn.example.net", Details: []Detail{{Path: "name", Message: "enter a host name like vpn.example.net"}}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), hostLookupTimeout)
	defer cancel()
	start := time.Now()
	out, err := m.runner().Run(ctx, "getent", "hosts", name)
	res := &HostLookupResult{Addresses: []string{}, Seconds: time.Since(start).Seconds()}
	switch {
	case ctx.Err() != nil:
		res.Error = "no answer within " + hostLookupTimeout.String()
		return res, nil
	case err != nil && strings.TrimSpace(string(out)) == "":
		return res, nil // exit 2: no such name
	case err != nil:
		res.Error = logText(firstLine(string(out)))
		return res, nil
	}
	res.Addresses = getentAddresses(string(out))
	return res, nil
}

// getentAddresses are the addresses in getent hosts' lines, "address
// name [alias ...]", each once.
func getentAddresses(out string) []string {
	addrs := []string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		if s := a.Unmap().String(); !slices.Contains(addrs, s) {
			addrs = append(addrs, s)
		}
	}
	return addrs
}
