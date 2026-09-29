package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRemovalStore(t *testing.T) (*Store, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	r := &fakeRunner{}
	files := []File{
		{Name: "hostname.*", Path: "/etc/hostname.*", Match: `[a-z]+[0-9]+`, Apply: []string{"netstart", "{*}"},
			Remove: []string{"destroy", "{*}", "{}"}, Mode: 0640},
		{Name: "pf", Path: "/etc/pf.conf", Apply: []string{"pfctl", "-f", "{}"}, Confirm: true, Mode: 0600},
	}
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: files, Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")
	writeLive(t, root, "/etc/hostname.vlan30", "vnetid 30 parent em1\nup\n")
	return s, r, root
}

func exists(root, path string) bool {
	_, err := os.Stat(filepath.Join(root, path))
	return err == nil
}

func TestRemoveFile(t *testing.T) {
	s, r, root := newRemovalStore(t)
	if err := s.StageRemoval("hostname.vlan30"); err != nil {
		t.Fatal(err)
	}
	changes, err := s.Changes()
	if err != nil || len(changes) != 1 || !changes[0].Removed || !strings.Contains(changes[0].Diff, "-vnetid 30 parent em1") {
		t.Fatalf("changes %+v, %v", changes, err)
	}
	if !exists(root, "/etc/hostname.vlan30") {
		t.Fatal("staging a removal touched the live file")
	}
	e, err := s.Commit(context.Background(), CommitInfo{Message: "remove vlan30"})
	if err != nil {
		t.Fatal(err)
	}
	if exists(root, "/etc/hostname.vlan30") {
		t.Error("the file wasn't removed")
	}
	if !r.ran("destroy vlan30 " + filepath.Join(root, "/etc/hostname.vlan30")) {
		t.Errorf("Remove didn't run with the device and path: %v", r.commands())
	}
	if r.ran("netstart") {
		t.Error("a removed file was applied")
	}
	if len(e.Files) != 1 || !e.Files[0].Removed || !e.Files[0].Existed {
		t.Errorf("history %+v", e.Files)
	}
	if _, ok, _ := s.EntryContent(e.ID, "hostname.vlan30", false); ok {
		t.Error("the commit has contents for a removed file")
	}
	if old, ok, _ := s.EntryContent(e.ID, "hostname.vlan30", true); !ok || !strings.Contains(string(old), "vnetid 30") {
		t.Error("the removed file's old contents weren't kept")
	}
	if c, _ := s.Changes(); len(c) != 0 {
		t.Errorf("still staged after the commit: %+v", c)
	}
}

// Reverting a commit that removed a file puts it back and applies it,
// and restages the removal so it can be tried again.
func TestRevertRemoval(t *testing.T) {
	s, r, root := newRemovalStore(t)
	s.StageRemoval("hostname.vlan30")
	stage(t, s, "pf", "block\n") // a Confirm file, so the commit waits
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Revert(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readLive(t, root, "/etc/hostname.vlan30"); got != "vnetid 30 parent em1\nup\n" {
		t.Errorf("not restored: %q", got)
	}
	if !r.ran("netstart vlan30") {
		t.Errorf("the restored file wasn't applied: %v", r.commands())
	}
	changes, _ := s.Changes()
	removed := false
	for _, c := range changes {
		removed = removed || (c.File.Name == "hostname.vlan30" && c.Removed)
	}
	if !removed {
		t.Errorf("the removal wasn't restaged: %+v", changes)
	}
}

func TestStageRemovalEdges(t *testing.T) {
	s, _, root := newRemovalStore(t)

	// A file that must exist to be loaded can't be removed.
	if err := s.StageRemoval("pf"); err == nil {
		t.Error("removing pf.conf was staged")
	}
	// Removing what isn't there stages nothing.
	if err := s.StageRemoval("hostname.vlan99"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Changes(); len(c) != 0 {
		t.Errorf("a missing file was staged for removal: %+v", c)
	}
	// Staging contents replaces a removal, and discarding forgets it.
	s.StageRemoval("hostname.vlan30")
	stage(t, s, "hostname.vlan30", "vnetid 31 parent em1\nup\n")
	if c, _ := s.Changes(); len(c) != 1 || c[0].Removed {
		t.Errorf("contents didn't replace the removal: %+v", c)
	}
	s.StageRemoval("hostname.vlan30")
	if err := s.Discard("hostname.vlan30"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Changes(); len(c) != 0 {
		t.Errorf("discard left %+v", c)
	}
	// A hand edit after staging the removal blocks the commit and is
	// kept.
	s.StageRemoval("hostname.vlan30")
	writeLive(t, root, "/etc/hostname.vlan30", "vnetid 30 parent em1\nmtu 9000\nup\n")
	_, err := s.Commit(context.Background(), CommitInfo{})
	var drift *DriftError
	if !errors.As(err, &drift) || !exists(root, "/etc/hostname.vlan30") {
		t.Errorf("drift: %v", err)
	}
}
