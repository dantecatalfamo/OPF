// Package sysinfo reads the running system's state from the output of
// OpenBSD's own tools: sysctl, vmstat, df, netstat, ifconfig, pfctl,
// tcpdump and ping. Each parser is a pure function of a command's
// output, so it's tested against output captured on real systems
// (testdata/<release>/), and the mock server feeds the same parsers
// simulated output.
//
// The parsers never panic. Output they don't recognise is skipped
// rather than guessed at, and a value that can't be read is left zero,
// so a format change shows up as missing information, not wrong
// information.
package sysinfo

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// lines splits command output into lines, without the trailing empty
// one.
func lines(out string) []string {
	var ls []string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ls = append(ls, sc.Text())
	}
	return ls
}

// ParseSysctl reads `sysctl name ...` output into a map. A value that
// continues onto more lines (kern.version) keeps its newlines; lines
// sysctl prints for names it doesn't know ("sysctl: ...") are skipped.
func ParseSysctl(out string) map[string]string {
	vals := map[string]string{}
	last := ""
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "sysctl: ") {
			last = ""
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok && isSysctlName(k) {
			vals[k] = v
			last = k
			continue
		}
		if last != "" {
			vals[last] += "\n" + l
		}
	}
	for k, v := range vals {
		vals[k] = strings.TrimRight(v, "\n\t ")
	}
	return vals
}

func isSysctlName(s string) bool {
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// CPUTicks is kern.cp_time: clock ticks spent in each state since boot.
type CPUTicks struct {
	User, Nice, System, Spin, Interrupt, Idle uint64
}

// ParseCPUTicks reads kern.cp_time's value ("301,0,217,39,12,42423").
func ParseCPUTicks(v string) (CPUTicks, error) {
	f := strings.Split(strings.TrimSpace(v), ",")
	if len(f) != 6 {
		return CPUTicks{}, fmt.Errorf("kern.cp_time: want 6 values, got %d", len(f))
	}
	var n [6]uint64
	for i, s := range f {
		x, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return CPUTicks{}, fmt.Errorf("kern.cp_time: %w", err)
		}
		n[i] = x
	}
	return CPUTicks{n[0], n[1], n[2], n[3], n[4], n[5]}, nil
}

func (t CPUTicks) total() uint64 {
	return t.User + t.Nice + t.System + t.Spin + t.Interrupt + t.Idle
}

// CPUUsage is the share of time in each state over an interval, in
// percent.
type CPUUsage struct {
	User      float64 `json:"user"`
	Nice      float64 `json:"nice"`
	System    float64 `json:"system"`
	Spin      float64 `json:"spin"`
	Interrupt float64 `json:"interrupt"`
	Idle      float64 `json:"idle"`
}

// Busy is everything but idle.
func (u CPUUsage) Busy() float64 { return 100 - u.Idle }

// Usage is the CPU use between an earlier reading and t. ok is false
// when no time has passed or the counters went backwards (a reboot).
func (t CPUTicks) Usage(earlier CPUTicks) (u CPUUsage, ok bool) {
	d := func(now, then uint64) (float64, bool) {
		if now < then {
			return 0, false
		}
		return float64(now - then), true
	}
	var parts [6]float64
	now := [6]uint64{t.User, t.Nice, t.System, t.Spin, t.Interrupt, t.Idle}
	then := [6]uint64{earlier.User, earlier.Nice, earlier.System, earlier.Spin, earlier.Interrupt, earlier.Idle}
	var sum float64
	for i := range now {
		x, good := d(now[i], then[i])
		if !good {
			return CPUUsage{}, false
		}
		parts[i] = x
		sum += x
	}
	if sum == 0 {
		return CPUUsage{}, false
	}
	pct := func(x float64) float64 { return x * 100 / sum }
	return CPUUsage{pct(parts[0]), pct(parts[1]), pct(parts[2]), pct(parts[3]), pct(parts[4]), pct(parts[5])}, true
}

// ParseLoadavg reads vm.loadavg's value ("0.01 0.04 0.02").
func ParseLoadavg(v string) ([3]float64, error) {
	var l [3]float64
	f := strings.Fields(v)
	if len(f) != 3 {
		return l, fmt.Errorf("vm.loadavg: want 3 values, got %d", len(f))
	}
	for i, s := range f {
		x, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return l, fmt.Errorf("vm.loadavg: %w", err)
		}
		l[i] = x
	}
	return l, nil
}

// ParseBoottime reads kern.boottime's value ("Tue Sep 29 16:09:55
// 2026"), which sysctl prints in the system's local time.
func ParseBoottime(v string, loc *time.Location) (time.Time, error) {
	t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(strings.Fields(v), " "), loc)
	if err != nil {
		// Single-digit days are space-padded by ctime(3); joining the
		// fields removed the padding.
		t, err = time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(strings.Fields(v), " "), loc)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("kern.boottime: %w", err)
	}
	return t, nil
}

// Sensor is one hw.sensors entry.
type Sensor struct {
	Device string `json:"device"` // cpu0, acpitz0, sd0
	Type   string `json:"type"`   // temp, fan, volt, drive, timedelta...
	Index  int    `json:"index"`
	// Value is what sysctl prints before the description, such as
	// "45.00 degC" or "online"; Number is its number, when it has one.
	Value       string   `json:"value"`
	Number      *float64 `json:"number,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	Description string   `json:"description,omitempty"`
	// Status is OK, WARNING, CRITICAL or UNKNOWN, when the sensor has
	// one.
	Status string `json:"status,omitempty"`
}

// ParseSensors reads `sysctl hw.sensors` output. The format, from
// sysctl(8)'s print_sensor, is:
//
//	hw.sensors.<device>.<type><index>=<value> [<unit>][ (<description>)][, <STATUS>][, <time>]
func ParseSensors(out string) []Sensor {
	var ss []Sensor
	for k, v := range ParseSysctl(out) {
		name, ok := strings.CutPrefix(k, "hw.sensors.")
		if !ok {
			continue
		}
		dev, typeIdx, ok := strings.Cut(name, ".")
		if !ok {
			continue
		}
		i := strings.IndexFunc(typeIdx, func(r rune) bool { return r >= '0' && r <= '9' })
		if i <= 0 {
			continue
		}
		idx, err := strconv.Atoi(typeIdx[i:])
		if err != nil {
			continue
		}
		s := Sensor{Device: dev, Type: typeIdx[:i], Index: idx}
		rest := v
		// The status and time follow the last ", "-separated parts; the
		// description is in parentheses before them.
		if j := strings.Index(rest, ", "); j >= 0 {
			for _, p := range strings.Split(rest[j+2:], ", ") {
				switch p {
				case "OK", "WARNING", "CRITICAL", "UNKNOWN":
					s.Status = p
				}
			}
			rest = rest[:j]
		}
		if j := strings.Index(rest, " ("); j >= 0 && strings.HasSuffix(rest, ")") {
			s.Description = rest[j+2 : len(rest)-1]
			rest = rest[:j]
		}
		s.Value = rest
		if f := strings.Fields(rest); len(f) > 0 {
			if x, err := strconv.ParseFloat(f[0], 64); err == nil {
				s.Number = &x
				s.Unit = strings.Join(f[1:], " ")
			}
		}
		ss = append(ss, s)
	}
	sortSensors(ss)
	return ss
}

func sortSensors(ss []Sensor) {
	less := func(a, b Sensor) bool {
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Index < b.Index
	}
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && less(ss[j], ss[j-1]); j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

// Memory is physical memory use, in bytes. Everything that isn't free
// is in use, including the kernel's and the buffer cache's. (vmstat's
// "pages wired" only counts pages wired by programs, so it isn't
// reported.)
type Memory struct {
	Total    uint64 `json:"total"`
	Free     uint64 `json:"free"`
	Active   uint64 `json:"active"`
	Inactive uint64 `json:"inactive"`
}

// ParseVmstatMemory reads `vmstat -s` for page counts, and physmem
// (hw.physmem) for the total.
func ParseVmstatMemory(out string, physmem uint64) (Memory, error) {
	counts := map[string]uint64{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		counts[strings.Join(f[1:], " ")] = n
	}
	page := counts["bytes per page"]
	if page == 0 {
		return Memory{}, fmt.Errorf("vmstat -s: no page size")
	}
	return Memory{
		Total:    physmem,
		Free:     counts["pages free"] * page,
		Active:   counts["pages active"] * page,
		Inactive: counts["pages inactive"] * page,
	}, nil
}

// Swap is swap space, in bytes.
type Swap struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// ParseSwapctl reads `swapctl -lk`: a row per device, and a Total row
// when there's more than one. No devices is no swap.
func ParseSwapctl(out string) Swap {
	var s, total Swap
	haveTotal := false
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] == "Device" {
			continue
		}
		blocks, err1 := strconv.ParseUint(f[1], 10, 64)
		used, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if f[0] == "Total" {
			total, haveTotal = Swap{blocks * 1024, used * 1024}, true
			continue
		}
		s.Total += blocks * 1024
		s.Used += used * 1024
	}
	if haveTotal {
		return total
	}
	return s
}

// Disk is one mounted filesystem, in bytes.
type Disk struct {
	Device    string `json:"device"`
	Mount     string `json:"mount"`
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
}

// ParseDf reads `df -kP` output. The mount point is everything after
// the capacity column, so one with spaces survives.
func ParseDf(out string) []Disk {
	var ds []Disk
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 6 || f[0] == "Filesystem" {
			continue
		}
		// Filesystem 1024-blocks Used Available Capacity Mounted-on
		c := -1
		for i := 4; i < len(f); i++ {
			if strings.HasSuffix(f[i], "%") {
				c = i
				break
			}
		}
		if c < 4 || c+1 >= len(f) {
			continue
		}
		n := make([]uint64, 3)
		ok := true
		for i := range 3 {
			x, err := strconv.ParseUint(f[c-3+i], 10, 64)
			if err != nil {
				ok = false
				break
			}
			n[i] = x * 1024
		}
		if !ok {
			continue
		}
		ds = append(ds, Disk{
			Device:    strings.Join(f[:c-3], " "),
			Mount:     strings.Join(f[c+1:], " "),
			Total:     n[0],
			Used:      n[1],
			Available: n[2],
		})
	}
	return ds
}

// TimeSync is OpenNTPD's state, from `ntpctl -s all`.
type TimeSync struct {
	Synced  bool   `json:"synced"`
	Stratum int    `json:"stratum,omitempty"`
	Status  string `json:"status"` // ntpctl's summary line
	// Source is the peer or sensor the clock follows (marked * by
	// ntpctl), and OffsetMs how far it is from the system clock.
	Source   string   `json:"source,omitempty"`
	OffsetMs *float64 `json:"offsetMs,omitempty"`
}

// ParseNtpctl reads `ntpctl -s all`: a summary line ("5/5 peers valid,
// ..., clock synced, stratum 1"), then each peer or sensor as a name
// line followed by its figures, the one in use starting with "*".
func ParseNtpctl(out string) (TimeSync, bool) {
	ls := lines(out)
	if len(ls) == 0 || !strings.Contains(ls[0], "valid") {
		return TimeSync{}, false
	}
	t := TimeSync{Status: strings.TrimSpace(ls[0])}
	for _, part := range strings.Split(t.Status, ", ") {
		if part == "clock synced" {
			t.Synced = true
		}
		if n, ok := strings.CutPrefix(part, "stratum "); ok {
			t.Stratum, _ = strconv.Atoi(n)
		}
	}
	for i := 1; i < len(ls); i++ {
		f := strings.Fields(ls[i])
		if len(f) < 7 || f[0] != "*" {
			continue
		}
		// wt tl st next poll offset ... for a peer; wt gd st next poll
		// offset correction for a sensor.
		if ms, ok := strings.CutSuffix(f[6], "ms"); ok {
			if x, err := strconv.ParseFloat(ms, 64); err == nil {
				t.OffsetMs = &x
			}
		}
		if n := strings.Fields(ls[i-1]); len(n) > 0 {
			t.Source = n[0]
		}
	}
	return t, true
}

// ParseSyspatch reads `syspatch -c`: the patches available, one name a
// line ("015_smtpd"), nothing when the system is up to date. Anything
// that isn't a patch name is skipped.
func ParseSyspatch(out string) []string {
	ps := []string{}
	for _, l := range lines(out) {
		l = strings.TrimSpace(l)
		num, name, ok := strings.Cut(l, "_")
		if !ok || len(num) != 3 || name == "" || len(l) > 64 {
			continue
		}
		if strings.IndexFunc(num, func(r rune) bool { return r < '0' || r > '9' }) >= 0 ||
			strings.IndexFunc(name, func(r rune) bool {
				return !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
			}) >= 0 {
			continue
		}
		ps = append(ps, l)
	}
	return ps
}
