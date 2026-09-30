// Package diag runs the diagnostic tools the UI offers (ping,
// traceroute, DNS lookups, port tests) in the privileged process.
//
// A request is a form, never a command line: each tool checks every
// field and builds a fixed argv from them, with "--" before anything the
// user typed, so a value can only ever be an address, a name or a
// number. Runs have a time limit and an output limit, there are only a
// few at once, and their output is kept for a while so the page can
// fetch it as it arrives.
package diag

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Request is a tool and its fields; each tool uses the ones it needs.
type Request struct {
	Tool string `json:"tool"` // ping, traceroute, dns, port

	// Host is an address or a host name (ping, traceroute, port).
	Host string `json:"host,omitempty"`
	// Family is "", "ipv4" or "ipv6": which to use for a host name.
	Family string `json:"family,omitempty"`

	// ping
	Count        int  `json:"count,omitempty"` // default 5
	Size         int  `json:"size,omitempty"`  // data bytes, default 56
	DontFragment bool `json:"dontFragment,omitempty"`

	// traceroute: "udp" (default) or "icmp"; port: "tcp" (default) or "udp".
	Protocol string `json:"protocol,omitempty"`
	MaxHops  int    `json:"maxHops,omitempty"` // default 30
	// ASNumbers looks up each hop's AS (traceroute -A).
	ASNumbers bool `json:"asNumbers,omitempty"`
	// Names resolves each hop's name (slower); off by default.
	Names bool `json:"names,omitempty"`

	// port
	Port int `json:"port,omitempty"`

	// dns: a name, or an address for a reverse lookup.
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"` // A, AAAA, MX...; default A
	// Server is the address to ask; empty asks this firewall's
	// resolver.
	Server string `json:"server,omitempty"`
	Trace  bool   `json:"trace,omitempty"` // +trace, from the root down
	DNSSEC bool   `json:"dnssec,omitempty"`
}

// Invalid is a request a tool won't run, with the field at fault.
type Invalid struct {
	Field   string
	Message string
}

func (e *Invalid) Error() string { return e.Field + ": " + e.Message }

func invalid(field, format string, args ...any) error {
	return &Invalid{Field: field, Message: fmt.Sprintf(format, args...)}
}

// command is what a request runs.
type command struct {
	argv    []string
	timeout time.Duration
}

// Tools are the tools, by name.
var Tools = map[string]func(Request) (command, error){
	"ping":       pingCommand,
	"traceroute": tracerouteCommand,
	"dns":        dnsCommand,
	"port":       portCommand,
}

// Build checks a request and returns the command it runs. It's exported
// for tests and for showing the command before running it.
func Build(r Request) (argv []string, timeout time.Duration, err error) {
	f, ok := Tools[r.Tool]
	if !ok {
		return nil, 0, invalid("tool", "no tool %q", r.Tool)
	}
	c, err := f(r)
	return c.argv, c.timeout, err
}

// host checks an address or host name. Addresses are written back
// normalized; names must be DNS host names (letters, digits, hyphens and
// dots, no label starting or ending with a hyphen), so none can look
// like an option.
func host(field, s string) (string, netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", netip.Addr{}, invalid(field, "enter an address or a name")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", netip.Addr{}, invalid(field, "leave out the %%zone")
		}
		return a.String(), a, nil
	}
	if !isHostName(s) {
		return "", netip.Addr{}, invalid(field, "%q isn't an address or a host name", s)
	}
	return s, netip.Addr{}, nil
}

func isHostName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// ipv6 says whether a request is for IPv6: its address is, or it asks
// for IPv6 for a name. It's an error to ask for the other family than
// an address has. OpenBSD's ping and traceroute have no -4 and -6; IPv6
// is ping6 and traceroute6.
func ipv6(r Request, a netip.Addr) (bool, error) {
	f, err := family(r, a)
	return len(f) == 1 && f[0] == "-6", err
}

// family returns -4 or -6 for a request (nc takes them): the address's
// own family, or the one asked for a name.
func family(r Request, a netip.Addr) ([]string, error) {
	switch r.Family {
	case "", "ipv4", "ipv6":
	default:
		return nil, invalid("family", "choose ipv4 or ipv6")
	}
	if a.IsValid() {
		if (r.Family == "ipv4" && !a.Is4()) || (r.Family == "ipv6" && a.Is4()) {
			return nil, invalid("family", "the address is %s", map[bool]string{true: "IPv4", false: "IPv6"}[a.Is4()])
		}
		if a.Is4() {
			return []string{"-4"}, nil
		}
		return []string{"-6"}, nil
	}
	switch r.Family {
	case "ipv4":
		return []string{"-4"}, nil
	case "ipv6":
		return []string{"-6"}, nil
	}
	return nil, nil
}

func number(field string, v, def, lo, hi int) (int, error) {
	if v == 0 {
		return def, nil
	}
	if v < lo || v > hi {
		return 0, invalid(field, "use %d to %d", lo, hi)
	}
	return v, nil
}

func pingCommand(r Request) (command, error) {
	h, a, err := host("host", r.Host)
	if err != nil {
		return command{}, err
	}
	v6, err := ipv6(r, a)
	if err != nil {
		return command{}, err
	}
	count, err := number("count", r.Count, 5, 1, 50)
	if err != nil {
		return command{}, err
	}
	// Up to jumbo frames, for finding a path's MTU.
	size, err := number("size", r.Size, 56, 1, 9000)
	if err != nil {
		return command{}, err
	}
	argv := []string{"ping"}
	if v6 {
		argv = []string{"ping6"}
	}
	argv = append(argv, "-c", strconv.Itoa(count), "-s", strconv.Itoa(size), "-w", "2")
	if r.DontFragment {
		if v6 {
			return command{}, invalid("dontFragment", "IPv6 packets are never fragmented on the way")
		}
		argv = append(argv, "-D")
	}
	argv = append(argv, "--", h)
	// One a second, and two seconds for the last reply.
	return command{argv, time.Duration(count+5) * time.Second}, nil
}

func tracerouteCommand(r Request) (command, error) {
	h, a, err := host("host", r.Host)
	if err != nil {
		return command{}, err
	}
	v6, err := ipv6(r, a)
	if err != nil {
		return command{}, err
	}
	hops, err := number("maxHops", r.MaxHops, 30, 1, 64)
	if err != nil {
		return command{}, err
	}
	argv := []string{"traceroute"}
	if v6 {
		argv = []string{"traceroute6"}
	}
	switch r.Protocol {
	case "", "udp":
	case "icmp":
		argv = append(argv, "-I")
	default:
		return command{}, invalid("protocol", "choose udp or icmp")
	}
	if r.ASNumbers {
		argv = append(argv, "-A")
	}
	if !r.Names {
		argv = append(argv, "-n")
	}
	argv = append(argv, "-m", strconv.Itoa(hops), "-q", "3", "-w", "2", "--", h)
	// Three probes of up to two seconds for each hop, at worst; hops
	// that answer are much quicker.
	return command{argv, time.Duration(min(hops*6, 180)) * time.Second}, nil
}

// dnsTypes are the record types a lookup can ask for.
var dnsTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "PTR": true,
	"SOA": true, "SRV": true, "TXT": true, "CAA": true, "DS": true, "DNSKEY": true,
	"HTTPS": true, "SVCB": true, "ANY": true,
}

func dnsCommand(r Request) (command, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return command{}, invalid("name", "enter a name, or an address to look up its name")
	}
	typ := strings.ToUpper(strings.TrimSpace(r.Type))
	if typ == "" {
		typ = "A"
	}
	if !dnsTypes[typ] {
		return command{}, invalid("type", "%q isn't a record type OPF looks up", r.Type)
	}
	argv := []string{"dig"}
	if r.Server != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(r.Server))
		if err != nil || a.Zone() != "" {
			return command{}, invalid("server", "enter the server's address")
		}
		argv = append(argv, "@"+a.String())
	} else if !r.Trace {
		// This firewall's resolver; with +trace dig asks the root
		// servers itself.
		argv = append(argv, "@127.0.0.1")
	}
	if a, err := netip.ParseAddr(name); err == nil {
		if a.Zone() != "" {
			return command{}, invalid("name", "leave out the %%zone")
		}
		// An address is always a reverse lookup.
		argv = append(argv, "-x", a.String())
	} else {
		// Names in DNS may hold underscores (_sip._tcp.example.com).
		if !isHostName(strings.ReplaceAll(name, "_", "a")) {
			return command{}, invalid("name", "%q isn't a DNS name", name)
		}
		argv = append(argv, "-q", name, "-t", typ)
	}
	argv = append(argv, "+time=3", "+tries=2")
	if r.Trace {
		argv = append(argv, "+trace")
	}
	if r.DNSSEC {
		argv = append(argv, "+dnssec")
	}
	timeout := 20 * time.Second
	if r.Trace {
		timeout = 45 * time.Second
	}
	return command{argv, timeout}, nil
}

func portCommand(r Request) (command, error) {
	h, a, err := host("host", r.Host)
	if err != nil {
		return command{}, err
	}
	fam, err := family(r, a)
	if err != nil {
		return command{}, err
	}
	if r.Port < 1 || r.Port > 65535 {
		return command{}, invalid("port", "use 1 to 65535")
	}
	argv := append([]string{"nc"}, fam...)
	argv = append(argv, "-z", "-v", "-w", "5")
	switch r.Protocol {
	case "", "tcp":
	case "udp":
		argv = append(argv, "-u")
	default:
		return command{}, invalid("protocol", "choose tcp or udp")
	}
	argv = append(argv, "--", h, strconv.Itoa(r.Port))
	return command{argv, 15 * time.Second}, nil
}
