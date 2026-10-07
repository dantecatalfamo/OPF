package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// The mock's unbound, while DNS activity is on: it writes the lines a
// real one would to the log OPF reads (appliance.Manager.DNSLog), a few
// days' worth when it's turned on and then a few lines every tick, from
// the mock's devices.

// mockClients ask for names: the mock's leases, a VPN device and the
// firewall itself. The thermostat asks for names that don't exist, as
// a misbehaving device might.
var mockClients = []struct {
	ip     string
	weight int
	names  []string
}{
	{"192.168.1.112", 6, []string{"www.google.com", "github.com", "slack.com", "api.github.com", "fonts.gstatic.com", "news.ycombinator.com", "www.youtube.com", "i.ytimg.com"}},
	{"192.168.1.118", 5, []string{"www.google.com", "outlook.office365.com", "teams.microsoft.com", "login.microsoftonline.com", "www.bbc.co.uk", "en.wikipedia.org"}},
	{"192.168.1.131", 2, []string{"outlook.office365.com", "www.google.com", "update.microsoft.com"}},
	{"192.168.1.144", 1, []string{"time.cloudflare.com", "status.example.net"}},
	{"192.168.20.101", 2, []string{"api.thermostat.example", "x7k2q.thermo-cdn.example", "p91zz.thermo-cdn.example", "nq0aa.thermo-cdn.example"}},
	{"192.168.20.102", 1, []string{"cam-relay.example.net", "firmware.camvendor.example"}},
	{"192.168.20.117", 3, []string{"netflix.com", "api-global.netflix.com", "occ-0-1-2.1.nflxso.net", "www.youtube.com"}},
	{"10.8.0.2", 2, []string{"www.google.com", "mail.google.com", "github.com", "imap.fastmail.com"}},
	{"127.0.0.1", 1, []string{"pool.ntp.org", "cdn.openbsd.org", "github.com"}},
}

// mockUnbound runs until ctx is done.
func mockUnbound(ctx context.Context, api *appliance.Manager, path string) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	on := false
	var seq uint32
	for {
		c, err := api.Live()
		keeps := err == nil && c.Model != nil && pf.KeepsDNSActivity(c.Model)
		switch {
		case !keeps:
			on = false
		case !on:
			// Just turned on: as if it had been on for a few days.
			on = true
			from := time.Now().Add(-time.Duration(min(c.Model.DNS.Activity.Days, 3)) * 24 * time.Hour)
			mockUnboundLines(path, c.Model, from, time.Now(), 40*time.Second, &seq)
		default:
			now := time.Now()
			mockUnboundLines(path, c.Model, now.Add(-3*time.Second), now, 500*time.Millisecond, &seq)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// mockUnboundLines appends a query every step from to to, from the
// mock's clients by weight, with the blocks the model's lists would make.
func mockUnboundLines(path string, m *pf.Model, from, to time.Time, step time.Duration, seq *uint32) {
	zones, blocking := mockBlocking(m)
	total := 0
	for _, c := range mockClients {
		total += c.weight
	}
	var b strings.Builder
	for at := from; at.Before(to); at = at.Add(step) {
		*seq++
		h := fnv.New32a()
		fmt.Fprint(h, *seq)
		r := h.Sum32()
		// Busier in the day than at night.
		if hr := at.Hour(); (hr < 7 || hr > 22) && r%3 != 0 {
			continue
		}
		pick := int(r % uint32(total))
		c := mockClients[0]
		for _, x := range mockClients {
			if pick < x.weight {
				c = x
				break
			}
			pick -= x.weight
		}
		stamp := fmt.Sprintf("[%d] unbound[29114:0]", at.Unix())
		f := float64(r/7%1000) / 1000
		if blocking && r%6 == 0 {
			name := mockBlockedNames[int(f*f*float64(len(mockBlockedNames)))]
			zone := zones[int(r/1000)%len(zones)]
			entry := "*." + strings.Join(strings.Split(name, ".")[max(0, len(strings.Split(name, "."))-2):], ".")
			if zone == pf.OwnLogName {
				entry = m.DNS.Blocked[int(r/6)%len(m.DNS.Blocked)] // r is a multiple of 6 here
				name = entry
				if under, ok := strings.CutPrefix(entry, "*."); ok {
					name = "stats." + under
				}
			}
			action, rcode := "rpz-local-data", "NOERROR"
			if m.DNS.BlockAnswer == pf.BlockAnswerNXDomain || zone == pf.OwnLogName {
				action, rcode = "rpz-nxdomain", "NXDOMAIN"
			}
			fmt.Fprintf(&b, "%s info: rpz: applied [%s] %s. %s %s@%d %s. A IN\n", stamp, zone, entry, action, c.ip, 1024+r%60000, name)
			fmt.Fprintf(&b, "%s reply: %s %s. A IN %s 0.000000 0 60\n", stamp, c.ip, name, rcode)
			continue
		}
		name := c.names[int(f*f*float64(len(c.names)))]
		rcode := "NOERROR"
		if strings.Contains(name, "thermo-cdn") {
			rcode = "NXDOMAIN"
		} else if r%97 == 0 {
			rcode = "SERVFAIL"
		}
		typ := []string{"A", "AAAA", "HTTPS"}[r%3]
		cached := 0
		if r%4 != 0 {
			cached = 1
		}
		fmt.Fprintf(&b, "%s reply: %s %s. %s IN %s %.6f %d 80\n", stamp, c.ip, name, typ, rcode, float64(r%90)/1000, cached)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("mock unbound: %v", err)
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("mock unbound: %v", err)
		return
	}
	defer file.Close()
	file.WriteString(b.String())
}
