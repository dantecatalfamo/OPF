// Package auth signs people in with the system's own accounts and keeps
// their sessions. It runs in the privileged process: the web process
// passes names, passwords and tokens on, and never decides who someone
// is.
package auth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Checker says whether a password is a user's.
type Checker interface {
	Check(ctx context.Context, user, password string) (bool, error)
}

// Limits on what's passed to a login helper.
const (
	MaxUser     = 32
	MaxPassword = 1024
)

var (
	userRE  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	styleRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
)

// BSDAuth checks passwords the way auth_userokay(3) does, without cgo:
// the user's login class names the login style (login.conf's auth-opf,
// or else auth; passwd if neither says), and that style's helper,
// /usr/libexec/auth/login_<style>, is run in response mode with the
// password on its back channel, descriptor 3. A class that asks for
// something other than a password (a YubiKey, RADIUS) gets its own
// helper, so a password alone isn't enough there either.
type BSDAuth struct {
	Passwd    string // master.passwd, for the user's login class
	LoginConf string
	Dir       string // the helpers
	Timeout   time.Duration
}

// SystemBSDAuth is the system's.
var SystemBSDAuth = BSDAuth{Passwd: "/etc/master.passwd", LoginConf: "/etc/login.conf", Dir: "/usr/libexec/auth", Timeout: 15 * time.Second}

func (b BSDAuth) Check(ctx context.Context, user, password string) (bool, error) {
	if !userRE.MatchString(user) || password == "" || len(password) > MaxPassword || strings.ContainsRune(password, 0) {
		return false, nil
	}
	// An unknown user still runs the helper, which takes as long, so
	// the time taken doesn't say whether the account exists.
	class, style := "default", "passwd"
	if u, err := lookupUser(b.Passwd, user); err == nil && u != nil {
		if u.Class != "" {
			class = u.Class
		}
		if u.expired(time.Now()) {
			user = "_opf-expired-" // checked, and rejected
		}
	}
	if s, err := loginStyle(b.LoginConf, class); err != nil {
		return false, err
	} else if s != "" {
		style = s
	}
	if !styleRE.MatchString(style) {
		return false, fmt.Errorf("login class %s asks for login style %q", class, style)
	}
	return b.helper(ctx, style, user, class, password)
}

func (b BSDAuth) helper(ctx context.Context, style, user, class, password string) (bool, error) {
	// Close-on-exec under ForkLock, so neither end leaks into a command
	// started meanwhile; the helper gets its end as descriptor 3.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false, err
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), "back"), os.NewFile(uintptr(fds[1]), "back")
	defer ours.Close()
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.Dir+"/login_"+style, "-s", "response", user, class)
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{theirs} // descriptor 3
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		theirs.Close()
		return false, fmt.Errorf("login_%s: %w", style, err)
	}
	theirs.Close()
	// The challenge (none) and the response, each ending in a NUL.
	ours.Write([]byte("\x00" + password + "\x00"))
	reply, _ := readAll(ours, 4096)
	err = cmd.Wait()
	ok := false
	sc := bufio.NewScanner(bytes.NewReader(reply))
	for sc.Scan() {
		switch strings.TrimSpace(sc.Text()) {
		case "authorize", "authorize secure":
			ok = true
		case "reject", "reject silent", "reject challenge":
			return false, nil
		}
	}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return false, nil // a rejection, or the account can't log in
	case err != nil:
		return false, fmt.Errorf("login_%s: %w: %s", style, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return ok, nil
}

func readAll(f *os.File, max int64) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(io.LimitReader(f, max))
	return b.Bytes(), err
}

// Static is a Checker of fixed passwords, for tests and the mock
// server.
type Static map[string]string

func (st Static) Check(_ context.Context, user, password string) (bool, error) {
	want, ok := st[user]
	return ok && subtle.ConstantTimeCompare([]byte(want), []byte(password)) == 1, nil
}
