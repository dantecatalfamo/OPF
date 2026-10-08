package sysinfo

import (
	"strconv"
	"strings"
)

// Rotation is how newsyslog rotates a log (newsyslog.conf(5)): how many
// old copies it keeps, the size it rotates at (0: by time instead), and
// whether the copies are compressed.
type Rotation struct {
	Count      int
	SizeKB     int
	Compressed bool
}

// Archive is the name of a log's i-th old copy (0 is the newest).
func (r Rotation) Archive(path string, i int) string {
	name := path + "." + strconv.Itoa(i)
	if r.Compressed {
		name += ".gz"
	}
	return name
}

// ParseNewsyslog reads newsyslog.conf: each log's rotation, by path.
func ParseNewsyslog(conf string) map[string]Rotation {
	out := map[string]Rotation{}
	for _, l := range lines(conf) {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		f := strings.Fields(l)
		// logfile [owner:group] mode count size when [flags] ...
		if len(f) >= 2 && strings.Contains(f[1], ":") {
			f = append(f[:1], f[2:]...)
		}
		if len(f) < 5 || !strings.HasPrefix(f[0], "/") {
			continue
		}
		count, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		r := Rotation{Count: count}
		if f[3] != "*" {
			if r.SizeKB, err = strconv.Atoi(f[3]); err != nil {
				continue
			}
		}
		if len(f) > 5 && !strings.HasPrefix(f[5], `"`) && !strings.HasPrefix(f[5], "/") {
			r.Compressed = strings.ContainsAny(f[5], "Z")
		}
		out[f[0]] = r
	}
	return out
}

// ParseLsSizes reads `ls -ln` of some files: each one's size, by path.
// Lines for files that aren't there (ls's errors) are skipped.
func ParseLsSizes(out string) map[string]int64 {
	sizes := map[string]int64{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		// mode links uid gid size month day time-or-year path
		if len(f) < 9 || !strings.HasPrefix(f[0], "-") {
			continue
		}
		n, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			continue
		}
		sizes[strings.Join(f[8:], " ")] = n
	}
	return sizes
}

// ParsePfTables reads `pfctl -vvs Tables`: how many tables, and the
// addresses in them all.
func ParsePfTables(out string) (tables, addresses int) {
	for _, l := range lines(out) {
		t := strings.TrimSpace(l)
		if a, ok := strings.CutPrefix(t, "Addresses:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
				addresses += n
			}
			continue
		}
		// A table's line: its flags, then its name.
		if !strings.HasPrefix(l, "\t") && len(strings.Fields(t)) == 2 && strings.Trim(strings.Fields(t)[0], "-cpaihrCh") == "" {
			tables++
		}
	}
	return tables, addresses
}
