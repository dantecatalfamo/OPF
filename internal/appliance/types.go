// Package appliance is OPF's configuration API: models in, commits out.
//
// The model (/var/opf/config.json) is a managed file like any other, so
// staging a model stages it together with every file generated from it,
// and a commit applies, snapshots and, if unconfirmed, reverts them as
// one unit. Manager runs in the privileged process and is the only
// thing that stages files; the web process reaches it through API.
package appliance

import (
	"errors"
	"fmt"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// API is everything the web process may do. Manager implements it in
// the privileged process; privsep.Client implements it over RPC.
type API interface {
	Status() (*Status, error)
	Live() (*Config, error)
	Staged() (*Staged, error)
	Stage(StageRequest) (*Staged, error)
	Discard() error
	Commit(CommitRequest) (*Commit, error)
	Commits() ([]Commit, error)
	GetCommit(id string) (*CommitDetail, error)
	Confirm(id string) (*Commit, error)
	Revert(id string) (*Commit, error)
	CommitConfig(id string, which Which) (*Config, error)
	LeaseNames() (*LeaseNames, error)
}

// NoVersion is the version of a configuration that doesn't exist yet.
const NoVersion = "none"

// Config is a model and its version, a hash of its contents used to
// detect concurrent changes.
type Config struct {
	Version string    `json:"version"`
	Model   *pf.Model `json:"model"`
}

// Staged is a model waiting to be committed, with the file changes it
// would make.
type Staged struct {
	Version string       `json:"version"`
	Base    string       `json:"base"` // live version it replaces
	Model   *pf.Model    `json:"model"`
	Changes []FileChange `json:"changes"`
}

// FileChange is one file a commit would change.
type FileChange struct {
	Path   string `json:"path"`
	Status string `json:"status"` // "added" or "modified"
	Diff   string `json:"diff"`
	// NeedsConfirm files are loaded provisionally and reverted unless
	// the commit is confirmed.
	NeedsConfirm bool `json:"needsConfirm,omitempty"`
	// Model marks OPF's own model file.
	Model bool `json:"model,omitempty"`
	// ModifiedOutside means the file changed on disk after it was staged.
	ModifiedOutside bool `json:"modifiedOutside,omitempty"`
}

// StageRequest stages a model. Base must be the live version the model
// was derived from, so edits to an out-of-date configuration fail
// instead of undoing someone else's commit.
type StageRequest struct {
	Base  string    `json:"base"`
	Model *pf.Model `json:"model"`
	// Overwrite lists files that were changed outside OPF and may be
	// replaced anyway.
	Overwrite []string `json:"overwrite,omitempty"`
}

// CommitRequest commits the staged model. Staged must be its version,
// so what's committed is exactly what the caller reviewed.
type CommitRequest struct {
	Staged  string              `json:"staged"`
	Message string              `json:"message"`
	Changes []config.ChangeNote `json:"changes"`
}

type CommitStatus string

const (
	StatusApplying  CommitStatus = "applying"
	StatusPending   CommitStatus = "pending" // waiting for confirmation
	StatusApplied   CommitStatus = "applied"
	StatusConfirmed CommitStatus = "confirmed"
	StatusReverted  CommitStatus = "reverted"
	StatusFailed    CommitStatus = "failed" // couldn't be applied and was reverted
)

// Commit is one entry in the configuration's history.
type Commit struct {
	ID       string              `json:"id"`
	Time     time.Time           `json:"time"`
	Status   CommitStatus        `json:"status"`
	Deadline *time.Time          `json:"deadline,omitempty"` // while pending
	Message  string              `json:"message"`
	Changes  []config.ChangeNote `json:"changes"`
	Files    []CommitFile        `json:"files"`
}

type CommitFile struct {
	Path         string `json:"path"`
	Created      bool   `json:"created,omitempty"`
	NeedsConfirm bool   `json:"needsConfirm,omitempty"`
	Model        bool   `json:"model,omitempty"`
}

// CommitDetail adds what each file's change was, and the commands run.
type CommitDetail struct {
	Commit
	Diffs []FileDiff `json:"diffs"`
	Log   string     `json:"log"`
}

type FileDiff struct {
	Path string `json:"path"`
	Diff string `json:"diff"`
}

// Status is small enough to poll.
type Status struct {
	Live    string  `json:"live"`
	Staged  string  `json:"staged,omitempty"`
	Pending *Commit `json:"pending,omitempty"`
}

// LeaseNames is what the DHCP lease watcher last did: the names
// dynamic leases have in DNS, and the leases that were refused one.
// Hostnames come from the clients, so they're shown sanitized.
type LeaseNames struct {
	Enabled    bool          `json:"enabled"`
	Checked    *time.Time    `json:"checked,omitempty"` // the last pass; absent before the first
	Registered []LeaseName   `json:"registered"`
	Refused    []RefusedName `json:"refused"`
	// Truncated says the lists were cut to MaxLeaseNames entries.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type LeaseName struct {
	Name string `json:"name"` // fully qualified, without the trailing dot
	IP   string `json:"ip"`
}

type RefusedName struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"` // as the client sent it, sanitized
	Reason   string `json:"reason"`
}

// Limits on what LeaseNames reports, whatever the leases file holds.
const (
	MaxLeaseNames    = 1000
	MaxHostnameRunes = 64
)

// Which picks a side of a commit: the configuration before or after it.
type Which string

const (
	Before Which = "before"
	After  Which = "after"
)

// Code classifies an Error for callers; the web layer maps it to an HTTP
// status.
type Code string

const (
	CodeInvalid         Code = "invalid"          // the request or model is invalid
	CodeConflict        Code = "conflict"         // a version didn't match
	CodeNotFound        Code = "not_found"        // no such commit
	CodeNothingStaged   Code = "nothing_staged"   // no staged model
	CodePending         Code = "commit_pending"   // a commit is waiting for confirmation
	CodeNotPending      Code = "not_pending"      // the commit isn't the one waiting
	CodeModifiedOutside Code = "modified_outside" // files changed outside OPF
	CodeCheckFailed     Code = "check_failed"     // a validator rejected a generated file
	CodeUnsupported     Code = "unsupported"      // something OPF can't do yet
	CodeInternal        Code = "internal"
)

// Error is the only error type API methods return.
type Error struct {
	Code    Code     `json:"code"`
	Message string   `json:"message"`
	Details []Detail `json:"details,omitempty"`
}

// Detail points at what went wrong: a model field or a file.
type Detail struct {
	Path    string `json:"path"`
	Message string `json:"message,omitempty"`
	Output  string `json:"output,omitempty"` // a validator's output
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError returns err as an *Error, wrapping anything else as internal.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: CodeInternal, Message: err.Error()}
}
