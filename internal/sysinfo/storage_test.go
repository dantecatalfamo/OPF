package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func readCaptured(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "openbsd-7.9", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseNewsyslog(t *testing.T) {
	rot := ParseNewsyslog(readCaptured(t, "newsyslog.conf.txt"))
	for path, want := range map[string]Rotation{
		"/var/log/daemon":  {Count: 5, SizeKB: 300, Compressed: true},
		"/var/log/pflog":   {Count: 3, SizeKB: 250, Compressed: true},
		"/var/log/authlog": {Count: 7, Compressed: true}, // weekly, by time
		"/var/log/wtmp":    {Count: 7},
	} {
		if got := rot[path]; got != want {
			t.Errorf("%s: %+v, want %+v", path, got, want)
		}
	}
	if got := (Rotation{Count: 3, Compressed: true}).Archive("/var/log/pflog", 0); got != "/var/log/pflog.0.gz" {
		t.Errorf("archive %s", got)
	}
}

func TestParseLsSizes(t *testing.T) {
	// From the VM, with old copies that aren't there yet.
	out := `ls: /var/log/daemon.0.gz: No such file or directory
-rw-r-----  1 0  0  186143 Oct  7 15:07 /var/log/daemon
-rw-------  1 0  0   17244 Oct  7 15:20 /var/log/pflog
`
	sizes := ParseLsSizes(out)
	if len(sizes) != 2 || sizes["/var/log/daemon"] != 186143 || sizes["/var/log/pflog"] != 17244 {
		t.Errorf("%v", sizes)
	}
}

func TestParsePfTables(t *testing.T) {
	n, addrs := ParsePfTables(readCaptured(t, "pfctl_-vvs_Tables.txt"))
	if n != 2 || addrs < 0 {
		t.Errorf("%d tables, %d addresses", n, addrs)
	}
}
