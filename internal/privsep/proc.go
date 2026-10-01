// Package privsep splits OPF into two processes, in the style of the
// OpenBSD base daemons:
//
//   - The parent keeps root, owns the configuration (appliance.Manager
//     and the commit engine under it) and runs every system command. It
//     never parses HTTP.
//   - The child is re-executed from the same binary as an unprivileged
//     user, serves the web UI on a listener opened by the parent, and
//     reaches the configuration only through the model-level calls of
//     appliance.API, over a socketpair. It can't name files or commands.
//
// Both processes restrict themselves with pledge(2) and unveil(2) on
// OpenBSD. Confirmation timers live in the parent, so an unconfirmed
// commit is still reverted if the web process crashes.
package privsep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
)

const childEnv = "OPF_PRIVSEP_CHILD"

// File descriptors handed to the child.
const (
	rpcFD      = 3
	listenerFD = 4
)

// IsChild reports whether this process is the unprivileged web process.
func IsChild() bool { return os.Getenv(childEnv) == "1" }

type ParentOptions struct {
	API *appliance.Manager
	// Accounts are who can sign in: every call but signing in needs a
	// session. Its TLS is the certificate the web process serves; nil
	// serves plain HTTP, which only loopback may (cmd/opf).
	Accounts ServeOptions
	// Listener is the socket the child serves, from ListenerFile.
	Listener *os.File
	// Credential is the unprivileged user the child runs as, from
	// Credential; nil keeps the current user (development).
	Credential *syscall.Credential
	Executable string // this binary, re-executed as the child
}

// RunParent runs the web process and answers its calls until ctx is
// done. If the web process exits it is started again.
func RunParent(ctx context.Context, opts ParentOptions) error {
	lf := opts.Listener
	defer lf.Close()
	cred := opts.Credential

	for {
		cmd, conn, err := spawn(opts.Executable, lf, cred)
		if err != nil {
			return err
		}
		go Serve(opts.API, opts.Accounts, conn)
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()

		select {
		case <-ctx.Done():
			cmd.Process.Signal(syscall.SIGTERM)
			<-exited
			conn.Close()
			return nil
		case err := <-exited:
			conn.Close()
			log.Printf("web process exited: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
			log.Printf("restarting web process")
		}
	}
}

// spawn starts the child with its end of a new socketpair and the
// listener, and returns the parent's end for the RPC. The parent's end
// stays an *os.File: net.FileConn would ask the socket's type with
// getsockopt, which the parent's pledge doesn't allow.
func spawn(exe string, listener *os.File, cred *syscall.Credential) (*exec.Cmd, *os.File, error) {
	// Hold ForkLock so the child's end can't leak into a command
	// started concurrently before it is marked close-on-exec.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
		// Non-blocking, so os.NewFile gives it to the poller and Close
		// interrupts a pending read.
		if err = syscall.SetNonblock(fds[0], true); err != nil {
			syscall.Close(fds[0])
			syscall.Close(fds[1])
		}
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("privsep: socketpair: %w", err)
	}
	conn := os.NewFile(uintptr(fds[0]), "privsep-parent")
	childEnd := os.NewFile(uintptr(fds[1]), "privsep-child")
	defer childEnd.Close()

	cmd := exec.Command(exe)
	cmd.Env = []string{childEnv + "=1"}
	// No cmd.Dir: the parent's unveil hides "/", so it can't chdir the
	// child there. The child does it itself, before its own sandbox.
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{childEnd, listener} // rpcFD, listenerFD
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if err := cmd.Start(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("privsep: starting web process: %w", err)
	}
	return cmd, conn, nil
}

// ListenerFile returns the file of a TCP listener, to hand to the child.
// Go checks the socket's type as it makes the file, which pledge only
// allows with "inet", so call it before SandboxParent: the parent never
// needs the network itself.
func ListenerFile(ln net.Listener) (*os.File, error) {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("privsep: need a TCP listener, got %T", ln)
	}
	return tl.File()
}

// Credential returns the uid and gid to run the child as. When OPF
// itself isn't root (development) the child keeps the current user.
// It reads /etc/passwd, so call it before SandboxParent unveils the
// filesystem.
func Credential(name string) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		log.Printf("not running as root; web process runs as uid %d", os.Geteuid())
		return nil, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("privsep: web process user: %w", err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	if uid == 0 || gid == 0 {
		return nil, fmt.Errorf("privsep: web process user %s must not be root", name)
	}
	// An empty Groups clears supplementary groups.
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, nil
}

// RunChild connects to the parent, sandboxes the process and calls
// serve with a client of the parent, which calls as whoever WithToken
// names. It exits the process if the parent goes away.
func RunChild(serve func(*Client, net.Listener) error) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("privsep: web process must not run as root")
	}
	// Out of whatever directory OPF was started in.
	if err := os.Chdir("/"); err != nil {
		return err
	}
	rpcFile := os.NewFile(rpcFD, "privsep-rpc")
	conn, err := net.FileConn(rpcFile)
	rpcFile.Close()
	if err != nil {
		return fmt.Errorf("privsep: rpc socket: %w", err)
	}
	lnFile := os.NewFile(listenerFD, "privsep-listener")
	ln, err := net.FileListener(lnFile)
	lnFile.Close()
	if err != nil {
		return fmt.Errorf("privsep: listener: %w", err)
	}
	client := NewClient(conn)
	go func() {
		err := client.Wait()
		log.Printf("lost privileged process: %v", err)
		os.Exit(1)
	}()
	if err := sandboxChild(); err != nil {
		return err
	}
	return serve(client, ln)
}
