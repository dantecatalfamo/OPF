package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Stream answers the diagnostic tools for the mock with output in the
// formats OpenBSD's ping, traceroute, dig and nc print, a line at a time
// with the delays the real ones have. Anything else is Run, all at once.
func (s mockSystem) Stream(ctx context.Context, line func(string), argv ...string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	// The target is what follows "--" (dig has none).
	target := ""
	if i := slices.Index(argv, "--"); i >= 0 && i+1 < len(argv) {
		target = argv[i+1]
	}
	var steps []mockStep
	switch argv[0] {
	case "ping":
		if slices.Contains(argv, "-q") {
			break // the gateway check: Run's summary
		}
		steps = mockPingRun(argv, target)
	case "traceroute":
		steps = mockTraceroute(argv, target)
	case "dig":
		steps = mockDig(argv)
	case "nc":
		steps = mockNc(argv, target)
	}
	if steps == nil {
		out, err := s.Run(ctx, argv...)
		for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			line(l)
		}
		return err
	}
	for _, st := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(st.after):
		}
		if st.exit != 0 {
			return mockExit(st.exit)
		}
		line(st.line)
	}
	return nil
}

// mockExit is a command's exit status, as *exec.ExitError reports it.
type mockExit int

func (e mockExit) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e mockExit) ExitCode() int { return int(e) }

// mockStep is a line of output after a delay, or with exit set, the
// command ending with that status.
type mockStep struct {
	after time.Duration
	line  string
	exit  int
}

func flagValue(argv []string, flag, def string) string {
	for i, a := range argv {
		if a == "--" {
			break
		}
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return def
}

// mockAddr turns a name into an address, the same one each time, so the
// mock can answer for names; "unreachable" names and 192.0.2.0/24
// (documentation) never answer.
func mockAddr(target string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(target); err == nil {
		return a, !netip.MustParsePrefix("192.0.2.0/24").Contains(a)
	}
	h := fnv.New32a()
	h.Write([]byte(target))
	n := h.Sum32()
	return netip.AddrFrom4([4]byte{93, 184, byte(n >> 8), byte(n)}), !strings.Contains(target, "unreachable")
}

func mockPingRun(argv []string, target string) []mockStep {
	a, up := mockAddr(target)
	count := 5
	fmt.Sscan(flagValue(argv, "-c", "5"), &count)
	size := 56
	fmt.Sscan(flagValue(argv, "-s", "56"), &size)
	steps := []mockStep{{0, fmt.Sprintf("PING %s (%s): %d data bytes", target, a, size), 0}}
	// Don't fragment, bigger than the WAN's 1500-byte MTU allows.
	if slices.Contains(argv, "-D") && size > 1472 {
		steps = append(steps, mockStep{0, "ping: sendmsg: Message too long", 0})
		return append(steps, mockStep{0, "", 1})
	}
	got := 0
	var rtts []float64
	for i := range count {
		if !up {
			continue
		}
		rtt := 8.2 + float64((i*37)%11)/10
		rtts = append(rtts, rtt)
		got++
		steps = append(steps, mockStep{time.Second, fmt.Sprintf("%d bytes from %s: icmp_seq=%d ttl=56 time=%.3f ms", size+8, a, i, rtt), 0})
	}
	if !up {
		steps = append(steps, mockStep{time.Duration(count+2) * time.Second, "", 0})
	}
	steps = append(steps, mockStep{0, "", 0}, mockStep{0, fmt.Sprintf("--- %s ping statistics ---", target), 0},
		mockStep{0, fmt.Sprintf("%d packets transmitted, %d packets received, %.1f%% packet loss", count, got, float64(count-got)*100/float64(count)), 0})
	if got > 0 {
		lo, hi, sum := rtts[0], rtts[0], 0.0
		for _, r := range rtts {
			lo, hi, sum = min(lo, r), max(hi, r), sum+r
		}
		steps = append(steps, mockStep{0, fmt.Sprintf("round-trip min/avg/max/std-dev = %.3f/%.3f/%.3f/0.312 ms", lo, sum/float64(got), hi), 0})
	} else {
		steps = append(steps, mockStep{0, "", 1})
	}
	return steps
}

func mockTraceroute(argv []string, target string) []mockStep {
	a, up := mockAddr(target)
	hops := 30
	fmt.Sscan(flagValue(argv, "-m", "30"), &hops)
	steps := []mockStep{{0, fmt.Sprintf("traceroute to %s (%s), %d hops max, 40 byte packets", target, a, hops), 0}}
	path := []string{"203.0.113.1", "198.51.100.1", "198.51.100.65", "192.0.2.254"}
	for i := 1; i <= hops; i++ {
		hop := ""
		switch {
		case i <= len(path):
			hop = path[i-1]
		case up && i == len(path)+1:
			hop = a.String()
		}
		if hop == "" {
			steps = append(steps, mockStep{6 * time.Second, fmt.Sprintf("%2d  * * *", i), 0})
			if i >= len(path)+3 {
				break // enough to show it; the real one keeps going
			}
			continue
		}
		t := 1.2 + float64(i)*2.3
		as := ""
		if slices.Contains(argv, "-A") {
			as = fmt.Sprintf(" [AS%d]", 64496+i)
		}
		steps = append(steps, mockStep{400 * time.Millisecond, fmt.Sprintf("%2d  %s%s  %.3f ms  %.3f ms  %.3f ms", i, hop, as, t, t+0.2, t+0.1), 0})
		if hop == a.String() {
			break
		}
	}
	return steps
}

func mockDig(argv []string) []mockStep {
	name, typ := flagValue(argv, "-q", ""), flagValue(argv, "-t", "A")
	server := "127.0.0.1"
	for _, a := range argv {
		if strings.HasPrefix(a, "@") {
			server = a[1:]
		}
	}
	answer := ""
	switch {
	case slices.Contains(argv, "-x"):
		rev := flagValue(argv, "-x", "")
		name, typ = rev+" (reverse)", "PTR"
		answer = "20.1.168.192.in-addr.arpa. 3600 IN PTR files.office.arpa."
		if !strings.HasPrefix(rev, "192.168.") {
			answer = ""
		}
	case strings.Contains(name, "nonexistent"):
	case typ == "A":
		a, _ := mockAddr(name)
		answer = fmt.Sprintf("%s.\t\t300\tIN\tA\t%s", strings.TrimSuffix(name, "."), a)
	case typ == "AAAA":
		answer = fmt.Sprintf("%s.\t\t300\tIN\tAAAA\t2001:db8::%x", strings.TrimSuffix(name, "."), len(name))
	case typ == "MX":
		answer = fmt.Sprintf("%s.\t\t3600\tIN\tMX\t10 mail.%s.", strings.TrimSuffix(name, "."), strings.TrimSuffix(name, "."))
	case typ == "TXT":
		answer = fmt.Sprintf("%s.\t\t3600\tIN\tTXT\t\"v=spf1 -all\"", strings.TrimSuffix(name, "."))
	default:
		answer = fmt.Sprintf("%s.\t\t3600\tIN\t%s\t; (mock)", strings.TrimSuffix(name, "."), typ)
	}
	status := "NOERROR"
	if answer == "" {
		status = "NXDOMAIN"
	}
	lines := []string{
		"", fmt.Sprintf("; <<>> dig 9.10.8-P1 <<>> %s", strings.Join(argv[1:], " ")),
		";; global options: +cmd", ";; Got answer:",
		fmt.Sprintf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: 41236", status),
		fmt.Sprintf(";; flags: qr rd ra ad; QUERY: 1, ANSWER: %d, AUTHORITY: 0, ADDITIONAL: 1", map[bool]int{true: 1, false: 0}[answer != ""]),
		"", ";; QUESTION SECTION:", fmt.Sprintf(";%s.\t\t\tIN\t%s", strings.TrimSuffix(name, "."), typ), "",
	}
	if answer != "" {
		lines = append(lines, ";; ANSWER SECTION:", answer, "")
	}
	lines = append(lines, ";; Query time: 12 msec", fmt.Sprintf(";; SERVER: %s#53(%s)", server, server),
		fmt.Sprintf(";; WHEN: %s", time.Now().Format("Mon Jan 02 15:04:05 MST 2006")), ";; MSG SIZE  rcvd: 56", "")
	steps := []mockStep{{150 * time.Millisecond, lines[0], 0}}
	for _, l := range lines[1:] {
		steps = append(steps, mockStep{0, l, 0})
	}
	return steps
}

func mockNc(argv []string, target string) []mockStep {
	a, up := mockAddr(target)
	port := argv[len(argv)-1]
	proto := "tcp"
	if slices.Contains(argv, "-u") {
		proto = "udp"
	}
	// Web, mail and DNS ports answer; others are closed.
	open := up && slices.Contains([]string{"22", "25", "53", "80", "443", "853"}, port)
	if !open {
		wait := 50 * time.Millisecond
		if !up {
			wait = 5 * time.Second
		}
		return []mockStep{{wait, fmt.Sprintf("nc: connect to %s port %s (%s) failed: Connection refused", a, port, proto), 0}, {0, "", 1}}
	}
	return []mockStep{{80 * time.Millisecond, fmt.Sprintf("Connection to %s %s port [%s/*] succeeded!", target, port, proto), 0}}
}
