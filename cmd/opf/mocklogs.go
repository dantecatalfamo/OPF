package main

import (
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// The mock's system logs, in syslogd's format: a day of what an office
// firewall writes, a line every few minutes, the same each run for a
// given time. The daemon log is mockDaemonLog's (mockdns.go).

type logSource struct {
	program string
	pid     int
	lines   []string
}

var mockLogSources = map[string][]logSource{
	"messages": {
		{"/bsd", 0, []string{"em1: link state changed to UP", "em0: watchdog timeout -- resetting", "vlan20: link state changed to UP"}},
		{"syslogd", 43102, []string{"restart", "dropped 3 messages from remote"}},
		{"ntpd", 1234, []string{"peer 162.159.200.1 now valid", "adjusting local clock by 0.004123s", "clock is now synced"}},
		{"dhcpleased", 3321, []string{"em0: 203.0.113.24 lease renewed", "em0: bound to 203.0.113.24 from 203.0.113.1"}},
	},
	"authlog": {
		{"sshd", 88213, []string{
			"Accepted publickey for admin from 192.168.1.112 port 51022 ssh2: ED25519 SHA256:3u1s9e...",
			"Invalid user oracle from 45.95.147.10 port 40122",
			"Connection closed by invalid user admin 185.220.101.4 port 51311 [preauth]",
			"Disconnected from user admin 192.168.1.112 port 51022",
			"Failed password for root from 162.142.125.9 port 58821 ssh2",
		}},
		{"doas", 0, []string{"admin ran command rcctl restart unbound as root from /home/admin", "admin ran command syspatch -c as root from /home/admin"}},
		{"login", 0, []string{"ROOT LOGIN (root) ON ttyC0"}},
	},
	"maillog": {
		{"smtpd", 7780, []string{"info: OpenSMTPD 7.9.0 starting", "8f21a3c4b0 mta delivery evpid=8f21a3c4b01 from=<root@gw.office.arpa> to=<admin@office.arpa> result=Ok stat=Sent"}},
	},
}

func mockSyslog(name string, now time.Time) string {
	srcs := mockLogSources[name]
	var b strings.Builder
	const every = 3 * time.Minute
	for at := now.Add(-24 * time.Hour).Truncate(every); !at.After(now); at = at.Add(every) {
		h := fnv.New32a()
		fmt.Fprint(h, name, at.Unix())
		r := h.Sum32()
		if r%3 != 0 {
			continue // quieter than every three minutes
		}
		s := srcs[int(r/3)%len(srcs)]
		tag := s.program
		if s.pid > 0 {
			tag = fmt.Sprintf("%s[%d]", s.program, s.pid)
		}
		fmt.Fprintf(&b, "%s gw %s: %s\n", at.Format(time.Stamp), tag, s.lines[int(r/7)%len(s.lines)])
	}
	return b.String()
}

// mockDmesg is the kernel's messages for the mock's PC Engines APU.
const mockDmesg = `OpenBSD 7.9 (GENERIC.MP) #15: Sun Sep 27 02:47:36 MDT 2026
    root@syspatch-79-amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP
real mem = 4261412864 (4063MB)
avail mem = 4112691200 (3922MB)
random: good seed from bootblocks
mpath0 at root
scsibus0 at mpath0: 256 targets
mainbus0 at root
bios0 at mainbus0: SMBIOS rev. 2.8 @ 0xcfe9b020 (13 entries)
bios0: vendor coreboot version "v4.19.0.1" date 01/31/2023
bios0: PC Engines apu4
acpi0 at bios0: ACPI 6.0
cpu0 at mainbus0: apid 0 (boot processor)
cpu0: AMD GX-412TC SOC, 998.28 MHz, 16-30-01
cpu0: 32KB 64b/line 2-way D-cache, 32KB 64b/line 2-way I-cache, 2MB 64b/line 16-way L2 cache
em0 at pci1 dev 0 function 0 "Intel I210" rev 0x03, msi, address 00:0d:b9:5a:3c:10
em1 at pci2 dev 0 function 0 "Intel I210" rev 0x03, msi, address 00:0d:b9:5a:3c:11
em2 at pci3 dev 0 function 0 "Intel I210" rev 0x03, msi, address 00:0d:b9:5a:3c:12
em3 at pci4 dev 0 function 0 "Intel I210" rev 0x03, msi, address 00:0d:b9:5a:3c:13
ahci0 at pci0 dev 17 function 0 "AMD Hudson-2 SATA" rev 0x40: apic 4 int 19, AHCI 1.3
sd0 at scsibus1 targ 0 lun 0: <ATA, SSD 32GB, S0417A> naa.5000000000000000
sd0: 30533MB, 512 bytes/sector, 62533296 sectors, thin
amdpcib0 at pci0 dev 20 function 3 "AMD Hudson-2 LPC" rev 0x11
root on sd0a (8c5e1a2b3c4d5e6f.a) swap on sd0b dump on sd0b
em0: watchdog timeout -- resetting
`
