package main

import (
	"fmt"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// What the mock answers for System › Storage.

// mockNewsyslog is the VM's newsyslog.conf, the logs OPF reads.
const mockNewsyslog = `/var/log/authlog	root:wheel	640  7     *    168   Z
/var/log/daemon				640  5     300  *     Z
/var/log/messages			644  5     300  *     Z
/var/log/pflog				600  3     250  *     ZB "pkill -HUP -u root -U root -t - -x pflogd"
`

// mockLogSizes is ls -ln of the logs: the current ones partly full and
// a few old copies, as a firewall that's run a few days has.
func mockLogSizes(paths []string) string {
	sizes := map[string]int{
		"/var/log/pflog": 183_402, "/var/log/pflog.0.gz": 41_220, "/var/log/pflog.1.gz": 39_874,
		"/var/log/daemon": 214_660, "/var/log/daemon.0.gz": 22_310, "/var/log/daemon.1.gz": 21_998, "/var/log/daemon.2.gz": 23_001,
		"/var/log/messages": 61_337, "/var/log/messages.0.gz": 9_812,
		"/var/log/authlog": 8_120, "/var/log/authlog.0.gz": 1_402,
	}
	var b strings.Builder
	for _, p := range paths {
		if n, ok := sizes[p]; ok {
			fmt.Fprintf(&b, "-rw-r-----  1 0  0  %d Oct  7 15:07 %s\n", n, p)
		} else {
			fmt.Fprintf(&b, "ls: %s: No such file or directory\n", p)
		}
	}
	return b.String()
}

// mockTables is pfctl -vvs Tables: OPF's own and one for each alias.
func mockTables(m *pf.Model) string {
	var b strings.Builder
	table := func(name string, n int) {
		fmt.Fprintf(&b, "-pa-r--\t%s\n\tAddresses:   %d\n\tCleared:     Wed Oct  7 09:00:00 2026\n", name, n)
	}
	table("bruteforce", 3)
	table("opf_local", 4)
	for _, a := range m.Firewall.Aliases {
		n := len(a.Entries)
		if a.Type == pf.AliasURL {
			n = 1184
		}
		table(a.Name, n)
	}
	return b.String()
}
