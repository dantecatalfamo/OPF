//go:build embedui

// Package ui holds the built web interface for the Go binary. Build it
// with `make build`, which runs the UI build and then compiles with the
// embedui tag.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// Files returns the built UI, rooted at dist.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded, so it's always there
	}
	return sub
}
