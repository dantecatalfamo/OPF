package appliance

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

func fileNamed(t *testing.T, files []ConfigFile, path string) ConfigFile {
	t.Helper()
	i := slices.IndexFunc(files, func(f ConfigFile) bool { return f.Path == path })
	if i < 0 {
		t.Fatalf("%s isn't listed", path)
	}
	return files[i]
}

func TestFiles(t *testing.T) {
	e := newEnv(t, time.Minute)
	files, err := e.m.Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/pf.conf", "/etc/dhcpd.conf", "/var/unbound/etc/unbound.conf", "/etc/hostname.em1", "/var/opf/config.json", pf.RcPath} {
		if f := fileNamed(t, files, p); !f.Exists || f.Outside || f.Staged != "" {
			t.Errorf("%s: %+v", p, f)
		}
	}
	if f := fileNamed(t, files, "/var/opf/config.json"); !f.Model {
		t.Error("config.json isn't the model")
	}
	if fileNamed(t, files, "/etc/pf.conf").Desc == "" {
		t.Error("no description")
	}

	// Only managed files can be read.
	for _, p := range []string{"/etc/master.passwd", "/etc/../etc/pf.conf", ""} {
		if _, err := e.m.File(p); code(err) != CodeNotFound {
			t.Errorf("%q: %v", p, err)
		}
	}
	v, err := e.m.File("/etc/pf.conf")
	if err != nil {
		t.Fatal(err)
	}
	if disk, _ := os.ReadFile(filepath.Join(e.root, "/etc/pf.conf")); v.Content != string(disk) {
		t.Error("the content isn't what's on disk")
	}

	// A hand edit: changed outside OPF, with what changed.
	dhcpd := filepath.Join(e.root, "/etc/dhcpd.conf")
	disk, _ := os.ReadFile(dhcpd)
	os.WriteFile(dhcpd, append(disk, []byte("# added by hand\n")...), 0644)
	v, err = e.m.File("/etc/dhcpd.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Outside || !strings.Contains(v.OutsideDiff, "+# added by hand") || !strings.Contains(v.OutsideDiff, "(as OPF left it)") {
		t.Errorf("outside: %v\n%s", v.Outside, v.OutsideDiff)
	}
	os.WriteFile(dhcpd, disk, 0644)

	// A staged change, and then the commit that wrote it.
	live := e.live()
	m := live.Model
	m.System.NTPServers = []string{"time.example"}
	if _, err := e.m.Stage(StageRequest{Base: live.Version, Model: m}); err != nil {
		t.Fatal(err)
	}
	files, _ = e.m.Files()
	if f := fileNamed(t, files, "/etc/ntpd.conf"); f.Staged != "modified" {
		t.Errorf("ntpd.conf: %+v", f)
	}
	if v, _ := e.m.File("/etc/ntpd.conf"); !strings.Contains(v.StagedDiff, "+servers time.example") {
		t.Errorf("staged diff:\n%s", v.StagedDiff)
	}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	files, _ = e.m.Files()
	if f := fileNamed(t, files, "/etc/ntpd.conf"); f.Commit == nil || f.Staged != "" {
		t.Errorf("after the commit: %+v", f)
	}
}
