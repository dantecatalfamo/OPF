//go:build !embedui

// Package ui holds the built web interface for the Go binary. Build it
// with `make build`, which runs the UI build and then compiles with the
// embedui tag.
package ui

import "io/fs"

// Files returns nil: this binary was built without the UI (go build or
// go test without the embedui tag), so only the API is served.
func Files() fs.FS { return nil }
