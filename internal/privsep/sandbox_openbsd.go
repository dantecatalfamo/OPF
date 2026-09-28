//go:build openbsd

package privsep

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"time"

	"golang.org/x/sys/unix"
)

// Directories searched for the commands the parent runs. Commands are
// only restricted until they exec; after that they run unconfined.
var execDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

// SandboxParent limits the privileged process to the directories it
// writes, the files it only reads, the commands it runs, and
// re-executing itself.
//
// "id" is needed because the child drops privileges between fork and
// exec, while still under the parent's pledge.
func SandboxParent(writable, readable []string, exe string) error {
	preload()
	for _, d := range writable {
		if err := unveil(d, "rwc"); err != nil {
			return err
		}
	}
	for _, p := range readable {
		if err := unveil(p, "r"); err != nil {
			return err
		}
	}
	for _, d := range execDirs {
		if err := unveil(d, "rx"); err != nil {
			return err
		}
	}
	if err := unveil(exe, "rx"); err != nil {
		return err
	}
	if err := unveil("/dev/null", "rw"); err != nil {
		return err
	}
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	return pledge("stdio rpath wpath cpath fattr chown proc exec id")
}

// sandboxChild hides the whole filesystem and allows only networking
// and I/O on descriptors already open. "rpath" is kept so a stray open
// fails with ENOENT under unveil instead of killing the process.
func sandboxChild() error {
	preload()
	if err := unveil("/var/empty", "r"); err != nil {
		return err
	}
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	return pledge("stdio rpath inet")
}

// preload triggers lazy file reads in the standard library before the
// filesystem disappears.
func preload() {
	time.Now().Local().Zone()    // /etc/localtime
	mime.TypeByExtension(".css") // /etc/mime.types etc.
}

func unveil(path, perms string) error {
	err := unix.Unveil(path, perms)
	if errors.Is(err, fs.ErrNotExist) {
		log.Printf("unveil: %s does not exist; skipping", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("unveil %s: %w", path, err)
	}
	return nil
}

func pledge(promises string) error {
	if err := unix.PledgePromises(promises); err != nil {
		return fmt.Errorf("pledge: %w", err)
	}
	return nil
}
