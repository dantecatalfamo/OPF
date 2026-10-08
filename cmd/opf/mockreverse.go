package main

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/web"
)

// What the mock answers for reverse DNS: the network's own names from
// its leases and reservations, as unbound would, and made-up names for
// the internet addresses its connections use. Some have none, as many
// don't.
var mockPTR = map[string]string{
	"9.9.9.9":         "dns9.quad9.net",
	"140.82.112.4":    "lb-140-82-112-4-iad.github.com",
	"151.101.1.140":   "",
	"52.94.236.248":   "",
	"142.250.72.110":  "lga25s71-in-f14.1e100.net",
	"104.16.132.229":  "",
	"93.184.215.14":   "",
	"17.253.144.10":   "usnyc3-vip-bx-008.aaplimg.com",
	"203.0.113.24":    "gw.office.example",
	"203.0.113.1":     "router.isp.example",
	"203.0.113.53":    "ns1.isp.example",
	"203.0.113.54":    "ns2.isp.example",
	"192.168.1.1":     "gw.office.arpa",
	"192.168.20.1":    "gw.office.arpa",
	"10.8.0.1":        "gw.office.arpa",
	"198.51.100.201":  "",
	"162.142.125.9":   "scanner-09.ch1.censys-scanner.com",
	"192.0.2.66":      "",
	"192.168.20.103":  "",
	"192.168.20.102":  "",
	"192.168.1.255":   "",
	"255.255.255.255": "",
}

func mockReverse(api *appliance.Manager) web.ReverseLookup {
	return func(ctx context.Context, addr string) ([]string, error) {
		// A real lookup takes a moment.
		select {
		case <-time.After(40 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if n, ok := mockPTR[addr]; ok {
			if n == "" {
				return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
			}
			return []string{n + "."}, nil
		}
		if ls, err := api.DHCPLeases(); err == nil {
			for _, l := range ls.Leases {
				if l.IP == addr && l.DNSName != "" {
					return []string{strings.TrimSuffix(l.DNSName, ".") + "."}, nil
				}
			}
		}
		if c, err := api.Live(); err == nil && c.Model != nil {
			for _, s := range c.Model.DHCP {
				for _, r := range s.Reservations {
					if r.IP == addr && r.Hostname != "" {
						return []string{r.Hostname + "." + c.Model.System.Domain + "."}, nil
					}
				}
			}
		}
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
}
