package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	ID       string      `json:"id"`
	Time     time.Time   `json:"time"`
	Status   Status      `json:"status"`
	Deadline time.Time   `json:"deadline,omitzero"`
	Files    []EntryFile `json:"files"`
	Log      string      `json:"log"`
}

type EntryFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
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
	return writeFileAtomic(filepath.Join(s.historyDir(e.ID), "manifest.json"), data, 0600)
}

// Entry loads one history entry.
func (s *Store) Entry(id string) (*Entry, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("invalid history id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(s.historyDir(id), "manifest.json"))
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
		if errors.Is(err, fs.ErrNotExist) {
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
func (s *Store) EntryDiff(e *Entry, ef EntryFile) (string, error) {
	return Diff(s.historyFile(e.ID, "old", ef.Path), s.historyFile(e.ID, "new", ef.Path),
		ef.Path+" (before)", ef.Path+" (after)")
}

// StageFromHistory stages a file as it was before (old) or after (new)
// a commit. Rolling back is just staging and committing an old version,
// so it gets the same checks and confirmation as any other change.
func (s *Store) StageFromHistory(id, name string, old bool) error {
	e, err := s.Entry(id)
	if err != nil {
		return err
	}
	f, err := s.Lookup(name)
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
		return s.Stage(f, data)
	}
	return fmt.Errorf("%s is not part of commit %s", name, id)
}
