//go:build !openbsd

package privsep

import "log"

// SandboxParent is a no-op outside OpenBSD.
func SandboxParent(writable []string, exe string) error {
	log.Printf("pledge and unveil are only available on OpenBSD; running unsandboxed")
	return nil
}

func sandboxChild() error { return nil }
