package appliance

import "slices"

// Read-only mode: OPF as a monitor for an OpenBSD machine configured by
// hand, watching it without taking it over. It's kept in four places,
// each enough by itself:
//
//   - ReadOnlyAPI refuses every API method that would change the
//     machine (readOnlyRefused), here and in the privileged process.
//   - Manager.ReadOnly() makes the runner for changes refuse everything
//     (run.Refuse), and stops the background work that changes things:
//     downloading lists, expiring table entries, sign-in accounts,
//     the traffic table, the firewall's own DNS servers.
//   - On OpenBSD, unveil(2) leaves every path read-only but OPF's own
//     state directory (cmd/opf).
//   - Sign-in accounts can't be made, changed or removed (privsep).
//
// It's on while the state directory has ReadOnlyMarker; opf -readonly
// makes it, and only taking the machine over takes it away, so leaving
// the flag off later doesn't hand OPF control.

// ReadOnlyMarker is the file in the state directory that keeps OPF in
// read-only mode.
const ReadOnlyMarker = "readonly"

// errReadOnly is every refusal's answer.
var errReadOnly = &Error{Code: CodeReadOnly, Message: "OPF is only monitoring this machine, so it changes nothing on it. Taking it over is under System › Take over."}

// ReadOnlyError is read-only mode's refusal.
func ReadOnlyError() *Error { return errReadOnly }

// readOnlyRefused are the methods that change the machine, or OPF's
// configuration of it. Every other method only looks (or keeps OPF's
// own data: forgetting traffic, sending a test notification), and
// TestReadOnlyAPIClassifiesEveryMethod checks each method is one or the
// other.
var readOnlyRefused = []string{
	"Stage", "Discard", "Commit", "Confirm", "Revert",
	"KillState", "TableChange", "RefreshAlias", "RefreshDNSList", "AuthpfEnd",
	"ServiceAction", "DNSTool",
	"SetWebhookSecret", "NewTunnelKey", "ImportTunnelKey", "SetPresharedKey",
}

// readOnlyAllowed are the rest: looking, and what changes only OPF's
// own records.
var readOnlyAllowed = []string{
	"Status", "Live", "Staged", "Commits", "GetCommit", "CommitConfig",
	"LeaseNames", "DHCPLeases", "ARPTable", "RoutingTable", "System", "Interfaces", "Gateways",
	"Files", "File", "Updates", "CheckUpdates",
	"PfStatus", "PfStats", "PfStates", "RuleCounters", "FirewallLog",
	"StartTool", "ToolRun", "CancelTool", "LookupHost",
	"Tables", "TableEntries", "TableFind", "AuthpfSessions", "Services", "Service",
	"DNSLists", "DNSStats", "DNSBlocked", "Storage", "Devices", "Device",
	"DNSActivity", "DNSDeviceActivity", "DNSNameActivity", "ForgetDNSActivity",
	"Traffic", "TrafficDevice", "ForgetTraffic", "Metrics", "Events", "SystemLog",
	"Webhooks", "NewDeviceKey", "TestWebhook",
	// Importing only reads; taking over is the way out of read-only
	// mode, and writes only the state directory before OPF starts again
	// (takeover.go).
	"Import", "TakeOver",
}

// ReadOnlyRefuses says whether read-only mode refuses an API method
// outright, for the privileged process's check of each call. Of
// ServiceAction and DNSTool only the parts that change things are
// refused, by the Manager itself.
func ReadOnlyRefuses(method string) bool {
	return slices.Contains(readOnlyRefused, method) && method != "ServiceAction" && method != "DNSTool"
}

// ReadOnlyAPI is api with everything that would change the machine
// refused.
func ReadOnlyAPI(api API) API { return readOnlyAPI{API: api} }

// ReadOnlyWhile is api with everything that would change the machine
// refused while on says so: the mock's, which leaves read-only mode in
// place when it's taken over.
func ReadOnlyWhile(api API, on func() bool) API { return readOnlyAPI{API: api, on: on} }

type readOnlyAPI struct {
	API
	on func() bool // nil: always
}

func (r readOnlyAPI) refuse() bool { return r.on == nil || r.on() }

func (r readOnlyAPI) Stage(req StageRequest) (*Staged, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.Stage(req)
}

func (r readOnlyAPI) Discard() error {
	if r.refuse() {
		return errReadOnly
	}
	return r.API.Discard()
}

func (r readOnlyAPI) Commit(req CommitRequest) (*Commit, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.Commit(req)
}

func (r readOnlyAPI) Confirm(id string) (*Commit, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.Confirm(id)
}

func (r readOnlyAPI) Revert(id string) (*Commit, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.Revert(id)
}

func (r readOnlyAPI) KillState(req KillStateRequest) error {
	if r.refuse() {
		return errReadOnly
	}
	return r.API.KillState(req)
}

func (r readOnlyAPI) TableChange(req TableChangeRequest) error {
	if r.refuse() {
		return errReadOnly
	}
	return r.API.TableChange(req)
}

func (r readOnlyAPI) RefreshAlias(id string) (*TableStatus, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.RefreshAlias(id)
}

func (r readOnlyAPI) RefreshDNSList(id string) (*DNSListStatus, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.RefreshDNSList(id)
}

func (r readOnlyAPI) AuthpfEnd(req AuthpfEndRequest) error {
	if r.refuse() {
		return errReadOnly
	}
	return r.API.AuthpfEnd(req)
}

func (r readOnlyAPI) SetWebhookSecret(id string, req WebhookSecretRequest) (*WebhookSecretResult, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.SetWebhookSecret(id, req)
}

func (r readOnlyAPI) NewTunnelKey() (string, error) {
	if r.refuse() {
		return "", errReadOnly
	}
	return r.API.NewTunnelKey()
}

func (r readOnlyAPI) ImportTunnelKey(key string) (string, error) {
	if r.refuse() {
		return "", errReadOnly
	}
	return r.API.ImportTunnelKey(key)
}

func (r readOnlyAPI) SetPresharedKey(req PresharedKeyRequest) (*PresharedKey, error) {
	if r.refuse() {
		return nil, errReadOnly
	}
	return r.API.SetPresharedKey(req)
}

// ServiceAction only checks a service: starting, stopping and
// restarting are changes.
func (r readOnlyAPI) ServiceAction(req ServiceActionRequest) (*ServiceActionResult, error) {
	if req.Action != "check" && r.refuse() {
		return nil, errReadOnly
	}
	return r.API.ServiceAction(req)
}

// DNSTool only looks: forgetting cached answers changes unbound.
func (r readOnlyAPI) DNSTool(req DNSToolRequest) (*DNSToolResult, error) {
	if t, ok := dnsTools[req.Tool]; (!ok || t.change) && r.refuse() {
		return nil, errReadOnly
	}
	return r.API.DNSTool(req)
}
