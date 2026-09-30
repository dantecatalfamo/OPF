// Package run executes system commands. Everything OPF does to the
// live system goes through a Runner so it can be swapped for a dry-run
// implementation during development, and later for a privileged helper.
package run

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Runner interface {
	// Run executes argv and returns its combined output.
	Run(ctx context.Context, argv ...string) ([]byte, error)
}

// Exec runs commands for real.
type Exec struct {
	// Credential, when set, runs commands as that user: for a command
	// that handles untrusted input, such as a download, so a bug in it
	// isn't a bug running as root.
	Credential *syscall.Credential
}

func (e Exec) command(ctx context.Context, argv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if e.Credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: e.Credential}
	}
	return cmd
}

func (e Exec) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("run: empty command")
	}
	out, err := e.command(ctx, argv).CombinedOutput()
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

// Streamer runs a command and hands over its combined output a line at
// a time as it arrives, for tools whose output is worth watching (ping,
// traceroute). The error is the command's exit, as with Run.
type Streamer interface {
	Stream(ctx context.Context, line func(string), argv ...string) error
}

// maxLine is the longest line Stream passes on; the rest of a longer
// one is dropped.
const maxLine = 4096

func (e Exec) Stream(ctx context.Context, line func(string), argv ...string) error {
	if len(argv) == 0 {
		return fmt.Errorf("run: empty command")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	cmd := e.command(ctx, argv)
	cmd.Stdout, cmd.Stderr = w, w
	// A command's children can keep the pipe open after it exits.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		w.Close()
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	w.Close() // only the child writes now; its exit ends the reads
	readLines(r, line)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// readLines calls line for each line of r, cutting lines longer than
// maxLine.
func readLines(r io.Reader, line func(string)) {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		b, err := br.ReadSlice('\n')
		if len(b) > 0 {
			l := strings.TrimRight(string(b), "\r\n")
			if err == bufio.ErrBufferFull {
				// Skip to the end of an overlong line.
				for err == bufio.ErrBufferFull {
					_, err = br.ReadSlice('\n')
				}
			}
			line(l)
		}
		if err != nil && err != bufio.ErrBufferFull {
			return
		}
	}
}

func (d Dry) Stream(ctx context.Context, line func(string), argv ...string) error {
	out, err := d.Run(ctx, argv...)
	readLines(strings.NewReader(string(out)), line)
	return err
}
