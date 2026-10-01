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
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
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
	DHCPLeases() (*DHCPLeases, error)
	ARPTable() (*ARPTable, error)
	RoutingTable() (*RoutingTable, error)
	System() (*SystemStatus, error)
	Interfaces() (*InterfacesStatus, error)
	Gateways() (*GatewaysStatus, error)
	Updates() (*UpdatesStatus, error)
	CheckUpdates() (*UpdatesStatus, error)
	PfStatus() (*PfStatus, error)
	PfStates(PfStatesRequest) (*PfStates, error)
	KillState(KillStateRequest) error
	RuleCounters() (*RuleCounters, error)
	FirewallLog() (*FirewallLog, error)
	StartTool(diag.Request) (*diag.Run, error)
	ToolRun(id string, from int) (*diag.Run, error)
	CancelTool(id string) error
	Tables() ([]TableStatus, error)
	RefreshAlias(name string) (*TableStatus, error)
	DNSLists() ([]DNSListStatus, error)
	RefreshDNSList(id string) (*DNSListStatus, error)
	DNSStats() (*DNSStats, error)
	DNSBlocked() (*DNSBlocked, error)
	Metrics(MetricsRequest) (*Metrics, error)
	Events(EventsRequest) (*Events, error)
	SystemLog(SystemLogRequest) (*SystemLog, error)
	DNSTool(DNSToolRequest) (*DNSToolResult, error)
	Webhooks() ([]WebhookStatus, error)
	SetWebhookSecret(id string, req WebhookSecretRequest) (*WebhookSecretResult, error)
	// NewTunnelKey makes a WireGuard tunnel's key pair, keeping the
	// private key on the firewall; NewDeviceKey makes one for a device
	// and keeps nothing (wgkeys.go).
	NewTunnelKey() (string, error)
	NewDeviceKey() (*DeviceKey, error)
	TestWebhook(id string) (*WebhookStatus, error)
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
	Status string `json:"status"` // "added", "modified" or "removed"
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
	// Author is who's signed in, set by the privileged process from the
	// session; never read from a request.
	Author string `json:"-"`
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
	Author   string              `json:"author,omitempty"`
	Changes  []config.ChangeNote `json:"changes"`
	Files    []CommitFile        `json:"files"`
}

type CommitFile struct {
	Path         string `json:"path"`
	Created      bool   `json:"created,omitempty"`
	Removed      bool   `json:"removed,omitempty"`
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
	// Release is the running OpenBSD release (kern.osrelease), read
	// once; empty if it couldn't be.
	Release string `json:"release,omitempty"`
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
	// From is the hostname the device sent, sanitized, when Name was
	// rewritten from it.
	From string `json:"from,omitempty"`
}

type RefusedName struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"` // as the client sent it, sanitized
	Reason   string `json:"reason"`
}

// DHCPLeases is dhcpd's current leases, from its leases file.
type DHCPLeases struct {
	Leases []DHCPLease `json:"leases"` // by address
	// Truncated says the list was cut to MaxLeases entries.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DHCPLease struct {
	IP  string `json:"ip"`
	MAC string `json:"mac,omitempty"`
	// Hostname is what the device asked to be called, sanitized.
	Hostname string     `json:"hostname,omitempty"`
	Iface    string     `json:"iface,omitempty"` // the interface whose DHCP range holds it
	Starts   *time.Time `json:"starts,omitempty"`
	Ends     *time.Time `json:"ends,omitempty"` // absent: the lease doesn't end
	// DNSName is the name the lease has in DNS; DNSRefused says why the
	// name it asked for wasn't given. Both are empty when names from
	// leases are off, or it didn't ask for one.
	DNSName    string `json:"dnsName,omitempty"`
	DNSRefused string `json:"dnsRefused,omitempty"`
}

// Limits on what LeaseNames and DHCPLeases report, whatever the leases
// file holds.
const (
	MaxLeaseNames    = 1000
	MaxLeases        = 5000
	MaxHostnameRunes = 64
)

// ARPTable is the system's ARP cache, from `arp -an`.
type ARPTable struct {
	Entries []ARPEntry `json:"entries"`
	Error   string     `json:"error,omitempty"`
}

type ARPEntry struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Iface    string `json:"iface"`
	Expires  string `json:"expires,omitempty"`  // time until expiry, or "permanent"
	Flags    string `json:"flags,omitempty"`    // published, static, etc.
	Hostname string `json:"hostname,omitempty"` // reverse DNS if known
}

// RoutingTable is the system's routing table, from `netstat -rn`.
type RoutingTable struct {
	IPv4  []RouteEntry `json:"ipv4"`
	IPv6  []RouteEntry `json:"ipv6,omitempty"`
	Error string       `json:"error,omitempty"`
}

type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Flags       string `json:"flags"`
	Iface       string `json:"iface"`
	Priority    int    `json:"priority,omitempty"`
	// Source describes where the route came from (e.g., "static", "dhcp", "interface").
	Source string `json:"source,omitempty"`
}

// SystemStatus is the machine: what it is, how long it's been up, and
// how busy it is. Parts that couldn't be read are nil or empty, with a
// line in Errors each.
type SystemStatus struct {
	Hostname string `json:"hostname"`
	Release  string `json:"release"` // 7.9
	Version  string `json:"version"` // kern.version's first line
	Machine  string `json:"machine"` // amd64
	CPUModel string `json:"cpuModel"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	CPUs     int    `json:"cpus"`
	// BootedAt is when the system started.
	BootedAt *time.Time `json:"bootedAt,omitempty"`
	// Load is the 1, 5 and 15 minute load averages.
	Load    *[3]float64       `json:"load,omitempty"`
	CPU     *sysinfo.CPUUsage `json:"cpu,omitempty"`
	Memory  *sysinfo.Memory   `json:"memory,omitempty"`
	Swap    *sysinfo.Swap     `json:"swap,omitempty"`
	Disks   []sysinfo.Disk    `json:"disks"`
	Sensors []sysinfo.Sensor  `json:"sensors"`
	// Time is nil when ntpd isn't running.
	Time   *sysinfo.TimeSync `json:"time,omitempty"`
	Errors []string          `json:"errors"`
}

// InterfacesStatus is every interface on the system, configured by OPF
// or not, by device name.
type InterfacesStatus struct {
	Interfaces []InterfaceState `json:"interfaces"`
	Errors     []string         `json:"errors"`
}

// InterfaceState is an interface as ifconfig shows it, its counters
// since it was created, and its traffic in bits per second over the
// last few seconds (nil until there are two readings).
type InterfaceState struct {
	sysinfo.Interface
	Counters *sysinfo.Counters `json:"counters,omitempty"`
	RxBps    *float64          `json:"rxBps,omitempty"`
	TxBps    *float64          `json:"txBps,omitempty"`
}

// GatewaysStatus is each model gateway's health, by gateway id.
type GatewaysStatus struct {
	Gateways map[string]GatewayHealth `json:"gateways"`
}

// GatewayHealth is the result of pinging a gateway.
type GatewayHealth struct {
	Address string   `json:"address,omitempty"` // what was pinged
	Online  bool     `json:"online"`
	LossPct float64  `json:"lossPct"`
	RttMs   *float64 `json:"rttMs,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// UpdatesStatus is the last check for security patches.
type UpdatesStatus struct {
	CheckedAt *time.Time `json:"checkedAt,omitempty"` // nil until the first check finishes
	Checking  bool       `json:"checking"`
	Patches   []string   `json:"patches"`
	Error     string     `json:"error,omitempty"`
}

// PfStatus is pf's own state: on or off, the state table, and traffic
// on the statistics interface.
type PfStatus struct {
	Info *sysinfo.PfInfo `json:"info,omitempty"`
	// StateLimit is the state table's hard limit (pfctl -s memory).
	StateLimit uint64 `json:"stateLimit,omitempty"`
	// BlockedPerSec is packets blocked per second on the statistics
	// interface over the last few seconds.
	BlockedPerSec *float64 `json:"blockedPerSec,omitempty"`
	Errors        []string `json:"errors"`
}

// PfStatesRequest asks for a page of the state table: the states whose
// addresses contain Query, of one protocol (tcp, udp, icmp; empty for
// all), busiest first, from Offset, at most Limit (StatesPage if 0).
type PfStatesRequest struct {
	Query  string `json:"query,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// PfStates is a page of pf's state table: the connections through and
// to the firewall. Total is how many of the states read match; Read is
// how many were read, at most MaxStatesRead, with Truncated set when the
// table had more.
type PfStates struct {
	States    []PfStateEntry `json:"states"`
	Total     int            `json:"total"`
	Read      int            `json:"read"`
	Truncated bool           `json:"truncated,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// PfStateEntry is a state and the label of the rule that created it.
type PfStateEntry struct {
	sysinfo.PfState
	Label string `json:"label,omitempty"`
}

// KillStateRequest names a state by the ids pfctl -vv -s states prints.
type KillStateRequest struct {
	ID        string `json:"id"`
	CreatorID string `json:"creatorId"`
}

// RuleCounters are the loaded rules' counters, by OPF label.
type RuleCounters struct {
	Labels map[string]RuleCounter `json:"labels"`
	Error  string                 `json:"error,omitempty"`
}

// RuleCounter is how much a labelled rule has matched since it was
// loaded, and the states it has now.
type RuleCounter struct {
	Evaluations uint64 `json:"evaluations"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	States      uint64 `json:"states"`
}

// FirewallLog is the latest packets pf logged, newest first, at most
// MaxLogEntries.
type FirewallLog struct {
	Entries []FirewallLogEntry `json:"entries"`
	// RulesSince is when the loaded ruleset may last have changed;
	// entries before it have no label.
	RulesSince *time.Time `json:"rulesSince,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// FirewallLogEntry is a logged packet and the label of the rule that
// logged it, when that's known.
type FirewallLogEntry struct {
	sysinfo.PfLogEntry
	Label string `json:"label,omitempty"`
}

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
	CodeBusy            Code = "busy"             // too much is running; try again soon
	CodeUnauthorized    Code = "unauthorized"     // not signed in, or the name or password is wrong
	CodeForbidden       Code = "forbidden"        // signed in, but the role doesn't allow it
	CodeRateLimited     Code = "rate_limited"     // too many failed sign-ins; try again later
	CodeReauth          Code = "reauth_required"  // give your password again to do this
	CodeInternal        Code = "internal"
)

// Session is someone signed in, as the API shows it. The token that
// proves it is a cookie, never in a body.
type Session struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Role     string    `json:"role"` // view, operator or admin
	Source   string    `json:"source"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
}

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
