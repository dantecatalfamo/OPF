package config

import (
	"path/filepath"
	"slices"
)

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
