package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"
)

// A history entry lives in history/<id>/:
//
//	manifest.json   the Entry below
//	old/<path>      live contents before the commit (if the file existed)
//	new/<path>      committed contents

type Status string

const (
	StatusApplying  Status = "applying" // interrupted if seen at startup
	StatusPending   Status = "pending"  // waiting for confirmation
	StatusApplied   Status = "applied"
	StatusConfirmed Status = "confirmed"
	StatusReverted  Status = "reverted"
	StatusFailed    Status = "failed"
)

type Entry struct {
	ID       string       `json:"id"`
	Time     time.Time    `json:"time"`
	Status   Status       `json:"status"`
	Deadline time.Time    `json:"deadline,omitzero"`
	Message  string       `json:"message,omitempty"`
	Author   string       `json:"author,omitempty"` // who signed in made it
	Changes  []ChangeNote `json:"changes,omitempty"`
	Files    []EntryFile  `json:"files"`
	Log      string       `json:"log"`
}

// CommitInfo describes a commit for the people reading history later.
type CommitInfo struct {
	Message string
	Author  string
	Changes []ChangeNote
}

// ChangeNote is one change in a commit, in words: "Disabled rule
// “Allow LAN to anywhere” on LAN", in area "firewall".
type ChangeNote struct {
	Area    string `json:"area"`
	Summary string `json:"summary"`
}

type EntryFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Removed bool   `json:"removed,omitempty"` // the commit removed it
	Confirm bool   `json:"confirm"`
}

var idRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}\.[0-9]{3}$`)

func newID(now time.Time) string { return now.UTC().Format("20060102-150405.000") }

func (s *Store) historyDir(id string) string { return filepath.Join(s.dir, "history", id) }

func (s *Store) historyFile(id, which string, path string) string {
	return filepath.Join(s.historyDir(id), which, path)
}

func (s *Store) saveEntry(e *Entry) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.historyDir(e.ID), "manifest.json")
	if err := writeFileAtomic(path, data, 0600); err != nil {
		return err
	}
	s.logPath("record", "", path, fmt.Sprintf("commit %s, %s", e.ID, e.Status))
	return nil
}

// Entry loads one history entry.
func (s *Store) Entry(id string) (*Entry, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCommit, id)
	}
	data, err := os.ReadFile(filepath.Join(s.historyDir(id), "manifest.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownCommit, id)
	}
	if err != nil {
		return nil, err
	}
	var e Entry
	return &e, json.Unmarshal(data, &e)
}

// History lists commits, newest first.
func (s *Store) History() ([]*Entry, error) {
	dirents, err := os.ReadDir(filepath.Join(s.dir, "history"))
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, d := range dirents {
		if !idRE.MatchString(d.Name()) {
			continue
		}
		e, err := s.Entry(d.Name())
		if errors.Is(err, ErrUnknownCommit) {
			continue // manifest not written yet
		} else if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// EntryDiff shows what a commit changed in one file.
func (s *Store) EntryDiff(id, name string) (string, error) {
	e, err := s.Entry(id)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(e.Files, func(ef EntryFile) bool { return ef.Name == name })
	if i < 0 {
		return "", fmt.Errorf("%s is not part of commit %s", name, id)
	}
	ef := e.Files[i]
	return Diff(s.historyFile(e.ID, "old", ef.Path), s.historyFile(e.ID, "new", ef.Path),
		ef.Path+" (before)", ef.Path+" (after)")
}

// EntryContent returns a file of a commit as it was before (old) or
// after it. exists is false if the file didn't exist before the commit.
func (s *Store) EntryContent(id, name string, old bool) (data []byte, exists bool, err error) {
	e, err := s.Entry(id)
	if err != nil {
		return nil, false, err
	}
	i := slices.IndexFunc(e.Files, func(ef EntryFile) bool { return ef.Name == name })
	if i < 0 {
		return nil, false, fmt.Errorf("%w: %s is not part of commit %s", ErrUnknownFile, name, id)
	}
	ef := e.Files[i]
	which := "new"
	if old {
		if !ef.Existed {
			return nil, false, nil
		}
		which = "old"
	}
	data, err = os.ReadFile(s.historyFile(id, which, ef.Path))
	return data, err == nil, err
}

// StageFromHistory stages a file as it was before (old) or after (new)
// a commit. Rolling back is just staging and committing an old version,
// so it gets the same checks and confirmation as any other change.
func (s *Store) StageFromHistory(id, name string, old bool) error {
	e, err := s.Entry(id)
	if err != nil {
		return err
	}
	for _, ef := range e.Files {
		if ef.Name != name {
			continue
		}
		which := "new"
		if old {
			if !ef.Existed {
				return fmt.Errorf("%s did not exist before this commit", ef.Path)
			}
			which = "old"
		}
		data, err := os.ReadFile(s.historyFile(id, which, ef.Path))
		if err != nil {
			return err
		}
		return s.Stage(name, data)
	}
	return fmt.Errorf("%s is not part of commit %s", name, id)
}
