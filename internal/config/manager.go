package config

import (
	"context"
	"path/filepath"
	"slices"
)

// Manager is the full set of operations the web UI can perform. Store
// implements it directly; the privsep client implements it by calling
// a Store in the privileged process. Files are always named, never
// passed as a File, so the unprivileged side can't choose which
// commands run or which paths are written.
type Manager interface {
	Files() []File
	Live(name string) ([]byte, bool, error)
	Staged(name string) ([]byte, bool, error)
	Current(name string) ([]byte, error)
	Stage(name string, data []byte) error
	Discard(name string) error
	DiscardAll() error
	Changes() ([]Change, error)
	CheckContent(ctx context.Context, name string, data []byte) (string, bool, error)
	Commit(ctx context.Context) (*Entry, error)
	Pending() *Entry
	Confirm() error
	Revert(ctx context.Context) error
	History() ([]*Entry, error)
	Entry(id string) (*Entry, error)
	EntryDiff(id, name string) (string, error)
	StageFromHistory(id, name string, old bool) error
}

var _ Manager = (*Store)(nil)

// WritableDirs lists every directory the store writes to: its state
// directory and the directory of each managed file.
func (s *Store) WritableDirs() []string {
	dirs := []string{s.dir}
	for _, f := range s.files {
		if d := filepath.Dir(s.livePath(f)); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}
