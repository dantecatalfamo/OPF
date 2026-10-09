package appliance

import "slices"

// Read-only mode: OPF as a monitor for an OpenBSD machine configured by
// hand, watching it without taking it over. It's kept in four places,
// each enough by itself:
//
//   - ReadOnlyAPI refuses every API method that would change the
//     machine (readOnlyRefused), here and in the privileged process.
//   - Manager.ReadOnly makes the runner for changes refuse everything
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
	"StartTool", "ToolRun", "CancelTool",
	"Tables", "TableEntries", "TableFind", "AuthpfSessions", "Services", "Service",
	"DNSLists", "DNSStats", "DNSBlocked", "Storage", "Devices", "Device",
	"DNSActivity", "DNSDeviceActivity", "DNSNameActivity", "ForgetDNSActivity",
	"Traffic", "TrafficDevice", "ForgetTraffic", "Metrics", "Events", "SystemLog",
	"Webhooks", "NewDeviceKey", "TestWebhook",
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
func ReadOnlyAPI(api API) API { return readOnlyAPI{api} }

type readOnlyAPI struct{ API }

func (readOnlyAPI) Stage(StageRequest) (*Staged, error)       { return nil, errReadOnly }
func (readOnlyAPI) Discard() error                            { return errReadOnly }
func (readOnlyAPI) Commit(CommitRequest) (*Commit, error)     { return nil, errReadOnly }
func (readOnlyAPI) Confirm(string) (*Commit, error)           { return nil, errReadOnly }
func (readOnlyAPI) Revert(string) (*Commit, error)            { return nil, errReadOnly }
func (readOnlyAPI) KillState(KillStateRequest) error          { return errReadOnly }
func (readOnlyAPI) TableChange(TableChangeRequest) error      { return errReadOnly }
func (readOnlyAPI) RefreshAlias(string) (*TableStatus, error) { return nil, errReadOnly }
func (readOnlyAPI) RefreshDNSList(string) (*DNSListStatus, error) {
	return nil, errReadOnly
}
func (readOnlyAPI) AuthpfEnd(AuthpfEndRequest) error { return errReadOnly }
func (readOnlyAPI) SetWebhookSecret(string, WebhookSecretRequest) (*WebhookSecretResult, error) {
	return nil, errReadOnly
}
func (readOnlyAPI) NewTunnelKey() (string, error)          { return "", errReadOnly }
func (readOnlyAPI) ImportTunnelKey(string) (string, error) { return "", errReadOnly }
func (readOnlyAPI) SetPresharedKey(PresharedKeyRequest) (*PresharedKey, error) {
	return nil, errReadOnly
}

// ServiceAction only checks a service: starting, stopping and
// restarting are changes.
func (r readOnlyAPI) ServiceAction(req ServiceActionRequest) (*ServiceActionResult, error) {
	if req.Action != "check" {
		return nil, errReadOnly
	}
	return r.API.ServiceAction(req)
}

// DNSTool only looks: forgetting cached answers changes unbound.
func (r readOnlyAPI) DNSTool(req DNSToolRequest) (*DNSToolResult, error) {
	if t, ok := dnsTools[req.Tool]; !ok || t.change {
		return nil, errReadOnly
	}
	return r.API.DNSTool(req)
}
