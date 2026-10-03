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
var execDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
	"/usr/libexec/auth", // checking passwords (auth.BSDAuth)
}

// SandboxParent limits the privileged process to the directories it
// writes, the files it only reads, the commands it runs, and
// re-executing itself.
//
// "id" is needed because the child drops privileges between fork and
// exec, while still under the parent's pledge.
func SandboxParent(writable, readable []string, exe string) error {
	return sandboxRoot(writable, readable, exe, "stdio rpath wpath cpath fattr chown proc exec id")
}

// SandboxWatchdog limits a commit's watchdog (cmd/opf) to what reverting
// the commit takes, which is what the parent does, plus flock(2) for
// the state directory's lock. It runs nothing of its own, so its
// executable isn't unveiled.
func SandboxWatchdog(writable []string) error {
	return sandboxRoot(writable, nil, "", "stdio rpath wpath cpath fattr chown proc exec id flock")
}

func sandboxRoot(writable, readable []string, exe, promises string) error {
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
	if exe != "" {
		if err := unveil(exe, "rx"); err != nil {
			return err
		}
	}
	if err := unveil("/dev/null", "rw"); err != nil {
		return err
	}
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	return pledge(promises)
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

// SandboxSender limits the webhook sender (cmd/opf) to making
// connections: it sees only the CA certificates, the resolver's
// configuration and /etc/hosts, and can't write or run anything.
func SandboxSender() error {
	preload()
	for _, p := range []string{"/etc/ssl/cert.pem", "/etc/resolv.conf", "/etc/hosts"} {
		if err := unveil(p, "r"); err != nil {
			return err
		}
	}
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	return pledge("stdio rpath inet dns")
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
