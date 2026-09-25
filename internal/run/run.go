// Package run executes system commands. Everything OPF does to the
// live system goes through a Runner so it can be swapped for a dry-run
// implementation during development, and later for a privileged helper.
package run

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type Runner interface {
	// Run executes argv and returns its combined output.
	Run(ctx context.Context, argv ...string) ([]byte, error)
}

// Exec runs commands for real.
type Exec struct{}

func (Exec) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("run: empty command")
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return out, nil
}

// Dry logs commands instead of running them and always succeeds. It
// lets the UI be developed on machines that aren't OpenBSD.
type Dry struct {
	Log *log.Logger
}

func (d Dry) Run(ctx context.Context, argv ...string) ([]byte, error) {
	line := strings.Join(argv, " ")
	if d.Log != nil {
		d.Log.Printf("dry-run: %s", line)
	}
	return []byte("dry-run: " + line + "\n"), nil
}
