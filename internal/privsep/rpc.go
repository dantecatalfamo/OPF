package privsep

import (
	"fmt"
	"io"
	"log"
	"net/rpc"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/metrics"
)

// The web process can only call these methods: whole models in,
// commits out. It can't name files, paths or commands; the privileged
// process validates every model before generating anything from it.

// Result carries an API error in-band; net/rpc would otherwise flatten
// it to a string. Internal errors are logged in the privileged process
// and cross the socket without their details.
type Result struct{ Err *appliance.Error }

func (r *Result) remoteErr() error {
	if r.Err == nil {
		return nil // untyped: a nil *Error in an error isn't nil
	}
	return r.Err
}

func (r *Result) set(method string, err error) {
	if err == nil {
		return
	}
	e := appliance.AsError(err)
	if e.Code == appliance.CodeInternal {
		log.Printf("%s: %s", method, e.Message)
		e = &appliance.Error{Code: appliance.CodeInternal, Message: "internal error"}
	}
	r.Err = e
}

type (
	None             struct{}
	IDArgs           struct{ ID string }
	CommitConfigArgs struct {
		ID    string
		Which appliance.Which
	}

	StatusReply struct {
		Result
		Status *appliance.Status
	}
	ConfigReply struct {
		Result
		Config *appliance.Config
	}
	StagedReply struct {
		Result
		Staged *appliance.Staged
	}
	CommitReply struct {
		Result
		Commit *appliance.Commit
	}
	CommitsReply struct {
		Result
		Commits []appliance.Commit
	}
	DetailReply struct {
		Result
		Detail *appliance.CommitDetail
	}
	LeaseNamesReply struct {
		Result
		Names *appliance.LeaseNames
	}
	DHCPLeasesReply struct {
		Result
		Leases *appliance.DHCPLeases
	}
	ARPTableReply struct {
		Result
		Table *appliance.ARPTable
	}
	RoutingTableReply struct {
		Result
		Table *appliance.RoutingTable
	}
	SystemReply struct {
		Result
		System *appliance.SystemStatus
	}
	InterfacesReply struct {
		Result
		Interfaces *appliance.InterfacesStatus
	}
	GatewaysReply struct {
		Result
		Gateways *appliance.GatewaysStatus
	}
	UpdatesReply struct {
		Result
		Updates *appliance.UpdatesStatus
	}
	PfStatusReply struct {
		Result
		Status *appliance.PfStatus
	}
	PfStatesReply struct {
		Result
		States *appliance.PfStates
	}
	RuleCountersReply struct {
		Result
		Counters *appliance.RuleCounters
	}
	FirewallLogReply struct {
		Result
		Log *appliance.FirewallLog
	}
	ToolRunReply struct {
		Result
		Run *diag.Run
	}
	TablesReply struct {
		Result
		Tables []appliance.TableStatus
	}
	TableReply struct {
		Result
		Table *appliance.TableStatus
	}
	DNSListsReply struct {
		Result
		Lists []appliance.DNSListStatus
	}
	DNSListReply struct {
		Result
		List *appliance.DNSListStatus
	}
	WebhooksReply struct {
		Result
		Webhooks []appliance.WebhookStatus
	}
	WebhookReply struct {
		Result
		Webhook *appliance.WebhookStatus
	}
	WebhookSecretArgs struct {
		ID      string
		Request appliance.WebhookSecretRequest
	}
	WebhookSecretReply struct {
		Result
		Secret *appliance.WebhookSecretResult
	}
	DNSToolReply struct {
		Result
		Output *appliance.DNSToolResult
	}
	SystemLogReply struct {
		Result
		Log *appliance.SystemLog
	}
	EventsReply struct {
		Result
		Events *appliance.Events
	}
	MetricsReply struct {
		Result
		Metrics *appliance.Metrics
	}
	DNSStatsReply struct {
		Result
		Stats *appliance.DNSStats
	}
	DNSBlockedReply struct {
		Result
		Blocked *appliance.DNSBlocked
	}
	NameArgs    struct{ Name string }
	ToolRunArgs struct {
		ID   string
		From int
	}
	EmptyReply struct{ Result }
)

// Service exposes an appliance.Manager over net/rpc.
type Service struct {
	api  *appliance.Manager
	done chan struct{} // closed when the connection ends
}

func (s *Service) Status(_ None, r *StatusReply) error {
	var err error
	r.Status, err = s.api.Status()
	r.set("Status", err)
	return nil
}

func (s *Service) LeaseNames(_ None, r *LeaseNamesReply) error {
	var err error
	r.Names, err = s.api.LeaseNames()
	r.set("LeaseNames", err)
	return nil
}

func (s *Service) DHCPLeases(_ None, r *DHCPLeasesReply) error {
	var err error
	r.Leases, err = s.api.DHCPLeases()
	r.set("DHCPLeases", err)
	return nil
}

func (s *Service) ARPTable(_ None, r *ARPTableReply) error {
	var err error
	r.Table, err = s.api.ARPTable()
	r.set("ARPTable", err)
	return nil
}

func (s *Service) RoutingTable(_ None, r *RoutingTableReply) error {
	var err error
	r.Table, err = s.api.RoutingTable()
	r.set("RoutingTable", err)
	return nil
}

func (s *Service) System(_ None, r *SystemReply) error {
	var err error
	r.System, err = s.api.System()
	r.set("System", err)
	return nil
}

func (s *Service) Interfaces(_ None, r *InterfacesReply) error {
	var err error
	r.Interfaces, err = s.api.Interfaces()
	r.set("Interfaces", err)
	return nil
}

func (s *Service) Gateways(_ None, r *GatewaysReply) error {
	var err error
	r.Gateways, err = s.api.Gateways()
	r.set("Gateways", err)
	return nil
}

func (s *Service) Updates(_ None, r *UpdatesReply) error {
	var err error
	r.Updates, err = s.api.Updates()
	r.set("Updates", err)
	return nil
}

func (s *Service) CheckUpdates(_ None, r *UpdatesReply) error {
	var err error
	r.Updates, err = s.api.CheckUpdates()
	r.set("CheckUpdates", err)
	return nil
}

func (s *Service) PfStatus(_ None, r *PfStatusReply) error {
	var err error
	r.Status, err = s.api.PfStatus()
	r.set("PfStatus", err)
	return nil
}

func (s *Service) PfStates(a appliance.PfStatesRequest, r *PfStatesReply) error {
	var err error
	r.States, err = s.api.PfStates(a)
	r.set("PfStates", err)
	return nil
}

func (s *Service) KillState(a appliance.KillStateRequest, r *EmptyReply) error {
	r.set("KillState", s.api.KillState(a))
	return nil
}

func (s *Service) RuleCounters(_ None, r *RuleCountersReply) error {
	var err error
	r.Counters, err = s.api.RuleCounters()
	r.set("RuleCounters", err)
	return nil
}

func (s *Service) FirewallLog(_ None, r *FirewallLogReply) error {
	var err error
	r.Log, err = s.api.FirewallLog()
	r.set("FirewallLog", err)
	return nil
}

func (s *Service) StartTool(a diag.Request, r *ToolRunReply) error {
	var err error
	r.Run, err = s.api.StartTool(a)
	r.set("StartTool", err)
	return nil
}

func (s *Service) ToolRun(a ToolRunArgs, r *ToolRunReply) error {
	var err error
	r.Run, err = s.api.ToolRun(a.ID, a.From)
	r.set("ToolRun", err)
	return nil
}

func (s *Service) CancelTool(a IDArgs, r *EmptyReply) error {
	r.set("CancelTool", s.api.CancelTool(a.ID))
	return nil
}

func (s *Service) Tables(_ None, r *TablesReply) error {
	var err error
	r.Tables, err = s.api.Tables()
	r.set("Tables", err)
	return nil
}

func (s *Service) RefreshAlias(a NameArgs, r *TableReply) error {
	var err error
	r.Table, err = s.api.RefreshAlias(a.Name)
	r.set("RefreshAlias", err)
	return nil
}

func (s *Service) DNSLists(_ None, r *DNSListsReply) error {
	var err error
	r.Lists, err = s.api.DNSLists()
	r.set("DNSLists", err)
	return nil
}

func (s *Service) Webhooks(_ None, r *WebhooksReply) error {
	var err error
	r.Webhooks, err = s.api.Webhooks()
	r.set("Webhooks", err)
	return nil
}

func (s *Service) SetWebhookSecret(a WebhookSecretArgs, r *WebhookSecretReply) error {
	var err error
	r.Secret, err = s.api.SetWebhookSecret(a.ID, a.Request)
	r.set("SetWebhookSecret", err)
	return nil
}

func (s *Service) TestWebhook(a IDArgs, r *WebhookReply) error {
	var err error
	r.Webhook, err = s.api.TestWebhook(a.ID)
	r.set("TestWebhook", err)
	return nil
}

func (s *Service) DNSTool(a appliance.DNSToolRequest, r *DNSToolReply) error {
	var err error
	r.Output, err = s.api.DNSTool(a)
	r.set("DNSTool", err)
	return nil
}

func (s *Service) SystemLog(a appliance.SystemLogRequest, r *SystemLogReply) error {
	var err error
	r.Log, err = s.api.SystemLog(a)
	r.set("SystemLog", err)
	return nil
}

func (s *Service) Events(a appliance.EventsRequest, r *EventsReply) error {
	var err error
	r.Events, err = s.api.Events(a)
	r.set("Events", err)
	return nil
}

func (s *Service) Metrics(a appliance.MetricsRequest, r *MetricsReply) error {
	var err error
	r.Metrics, err = s.api.Metrics(a)
	r.set("Metrics", err)
	return nil
}

func (s *Service) DNSStats(_ None, r *DNSStatsReply) error {
	var err error
	r.Stats, err = s.api.DNSStats()
	r.set("DNSStats", err)
	return nil
}

func (s *Service) DNSBlocked(_ None, r *DNSBlockedReply) error {
	var err error
	r.Blocked, err = s.api.DNSBlocked()
	r.set("DNSBlocked", err)
	return nil
}

func (s *Service) RefreshDNSList(a IDArgs, r *DNSListReply) error {
	var err error
	r.List, err = s.api.RefreshDNSList(a.ID)
	r.set("RefreshDNSList", err)
	return nil
}

func (s *Service) Live(_ None, r *ConfigReply) error {
	var err error
	r.Config, err = s.api.Live()
	r.set("Live", err)
	return nil
}

func (s *Service) Staged(_ None, r *StagedReply) error {
	var err error
	r.Staged, err = s.api.Staged()
	r.set("Staged", err)
	return nil
}

func (s *Service) Stage(a appliance.StageRequest, r *StagedReply) error {
	var err error
	r.Staged, err = s.api.Stage(a)
	r.set("Stage", err)
	return nil
}

func (s *Service) Discard(_ None, r *EmptyReply) error {
	r.set("Discard", s.api.Discard())
	return nil
}

func (s *Service) Commit(a appliance.CommitRequest, r *CommitReply) error {
	var err error
	r.Commit, err = s.api.Commit(a)
	r.set("Commit", err)
	return nil
}

func (s *Service) Commits(_ None, r *CommitsReply) error {
	var err error
	r.Commits, err = s.api.Commits()
	r.set("Commits", err)
	return nil
}

func (s *Service) GetCommit(a IDArgs, r *DetailReply) error {
	var err error
	r.Detail, err = s.api.GetCommit(a.ID)
	r.set("GetCommit", err)
	return nil
}

func (s *Service) Confirm(a IDArgs, r *CommitReply) error {
	var err error
	r.Commit, err = s.api.Confirm(a.ID)
	r.set("Confirm", err)
	return nil
}

func (s *Service) Revert(a IDArgs, r *CommitReply) error {
	var err error
	r.Commit, err = s.api.Revert(a.ID)
	r.set("Revert", err)
	return nil
}

func (s *Service) CommitConfig(a CommitConfigArgs, r *ConfigReply) error {
	var err error
	r.Config, err = s.api.CommitConfig(a.ID, a.Which)
	r.set("CommitConfig", err)
	return nil
}

// Wait doesn't return while the connection is up. The child calls it
// so that it notices, and exits, when the parent goes away.
func (s *Service) Wait(_ None, _ *None) error {
	<-s.done
	return fmt.Errorf("shutting down")
}

// Serve answers calls on conn until it is closed.
func Serve(api *appliance.Manager, conn io.ReadWriteCloser) {
	srv := rpc.NewServer()
	svc := &Service{api: api, done: make(chan struct{})}
	if err := srv.RegisterName("OPF", svc); err != nil {
		panic(err) // only fails if Service's method set is malformed
	}
	// Reads are size-limited: the web process is untrusted, and gob
	// would otherwise allocate whatever a message claims to need.
	srv.ServeCodec(newServerCodec(conn))
	close(svc.done)
}

// Client implements appliance.API by calling a Service.
type Client struct {
	rpc *rpc.Client
}

var _ appliance.API = (*Client)(nil)

func NewClient(conn io.ReadWriteCloser) *Client {
	return &Client{rpc: rpc.NewClientWithCodec(newClientCodec(conn))}
}

func (c *Client) call(method string, args any, reply interface{ remoteErr() error }) error {
	if err := c.rpc.Call("OPF."+method, args, reply); err != nil {
		return &appliance.Error{Code: appliance.CodeInternal, Message: "privileged process: " + err.Error()}
	}
	return reply.remoteErr()
}

// Wait blocks until the connection to the parent is lost.
func (c *Client) Wait() error {
	return c.rpc.Call("OPF.Wait", None{}, &None{})
}

func (c *Client) Close() error { return c.rpc.Close() }

func (c *Client) Status() (*appliance.Status, error) {
	var r StatusReply
	err := c.call("Status", None{}, &r)
	return r.Status, err
}

func (c *Client) LeaseNames() (*appliance.LeaseNames, error) {
	var r LeaseNamesReply
	err := c.call("LeaseNames", None{}, &r)
	// gob sends empty slices as nothing; keep them empty lists.
	if r.Names != nil {
		if r.Names.Registered == nil {
			r.Names.Registered = []appliance.LeaseName{}
		}
		if r.Names.Refused == nil {
			r.Names.Refused = []appliance.RefusedName{}
		}
	}
	return r.Names, err
}

func (c *Client) DHCPLeases() (*appliance.DHCPLeases, error) {
	var r DHCPLeasesReply
	err := c.call("DHCPLeases", None{}, &r)
	if r.Leases != nil && r.Leases.Leases == nil {
		r.Leases.Leases = []appliance.DHCPLease{} // see LeaseNames
	}
	return r.Leases, err
}

func (c *Client) Live() (*appliance.Config, error) {
	var r ConfigReply
	err := c.call("Live", None{}, &r)
	return r.Config, err
}

func (c *Client) Staged() (*appliance.Staged, error) {
	var r StagedReply
	err := c.call("Staged", None{}, &r)
	return r.Staged, err
}

func (c *Client) Stage(req appliance.StageRequest) (*appliance.Staged, error) {
	var r StagedReply
	err := c.call("Stage", req, &r)
	return r.Staged, err
}

func (c *Client) Discard() error {
	return c.call("Discard", None{}, &EmptyReply{})
}

func (c *Client) Commit(req appliance.CommitRequest) (*appliance.Commit, error) {
	var r CommitReply
	err := c.call("Commit", req, &r)
	return r.Commit, err
}

func (c *Client) Commits() ([]appliance.Commit, error) {
	var r CommitsReply
	err := c.call("Commits", None{}, &r)
	return r.Commits, err
}

func (c *Client) GetCommit(id string) (*appliance.CommitDetail, error) {
	var r DetailReply
	err := c.call("GetCommit", IDArgs{id}, &r)
	return r.Detail, err
}

func (c *Client) Confirm(id string) (*appliance.Commit, error) {
	var r CommitReply
	err := c.call("Confirm", IDArgs{id}, &r)
	return r.Commit, err
}

func (c *Client) Revert(id string) (*appliance.Commit, error) {
	var r CommitReply
	err := c.call("Revert", IDArgs{id}, &r)
	return r.Commit, err
}

func (c *Client) CommitConfig(id string, which appliance.Which) (*appliance.Config, error) {
	var r ConfigReply
	err := c.call("CommitConfig", CommitConfigArgs{id, which}, &r)
	return r.Config, err
}

func (c *Client) ARPTable() (*appliance.ARPTable, error) {
	var r ARPTableReply
	err := c.call("ARPTable", None{}, &r)
	if r.Table != nil && r.Table.Entries == nil {
		r.Table.Entries = []appliance.ARPEntry{}
	}
	return r.Table, err
}

func (c *Client) RoutingTable() (*appliance.RoutingTable, error) {
	var r RoutingTableReply
	err := c.call("RoutingTable", None{}, &r)
	if r.Table != nil {
		if r.Table.IPv4 == nil {
			r.Table.IPv4 = []appliance.RouteEntry{}
		}
		if r.Table.IPv6 == nil {
			r.Table.IPv6 = []appliance.RouteEntry{}
		}
	}
	return r.Table, err
}

// gob leaves out empty slices and maps, so the replies below restore
// them: the JSON API promises [] and {}, never null.

func (c *Client) System() (*appliance.SystemStatus, error) {
	var r SystemReply
	err := c.call("System", None{}, &r)
	if s := r.System; s != nil {
		s.Disks = nonNil(s.Disks)
		s.Sensors = nonNil(s.Sensors)
		s.Errors = nonNil(s.Errors)
	}
	return r.System, err
}

func (c *Client) Interfaces() (*appliance.InterfacesStatus, error) {
	var r InterfacesReply
	err := c.call("Interfaces", None{}, &r)
	if s := r.Interfaces; s != nil {
		s.Interfaces = nonNil(s.Interfaces)
		s.Errors = nonNil(s.Errors)
		for i := range s.Interfaces {
			x := &s.Interfaces[i]
			x.Flags, x.Groups, x.IPv4, x.IPv6 = nonNil(x.Flags), nonNil(x.Groups), nonNil(x.IPv4), nonNil(x.IPv6)
			if w := x.WireGuard; w != nil {
				w.Peers = nonNil(w.Peers)
				for j := range w.Peers {
					w.Peers[j].AllowedIPs = nonNil(w.Peers[j].AllowedIPs)
				}
			}
		}
	}
	return r.Interfaces, err
}

func (c *Client) Gateways() (*appliance.GatewaysStatus, error) {
	var r GatewaysReply
	err := c.call("Gateways", None{}, &r)
	if s := r.Gateways; s != nil && s.Gateways == nil {
		s.Gateways = map[string]appliance.GatewayHealth{}
	}
	return r.Gateways, err
}

func (c *Client) Updates() (*appliance.UpdatesStatus, error) {
	var r UpdatesReply
	err := c.call("Updates", None{}, &r)
	if s := r.Updates; s != nil {
		s.Patches = nonNil(s.Patches)
	}
	return r.Updates, err
}

func (c *Client) CheckUpdates() (*appliance.UpdatesStatus, error) {
	var r UpdatesReply
	err := c.call("CheckUpdates", None{}, &r)
	if s := r.Updates; s != nil {
		s.Patches = nonNil(s.Patches)
	}
	return r.Updates, err
}

func (c *Client) PfStatus() (*appliance.PfStatus, error) {
	var r PfStatusReply
	err := c.call("PfStatus", None{}, &r)
	if s := r.Status; s != nil {
		s.Errors = nonNil(s.Errors)
		if s.Info != nil && s.Info.Counters == nil {
			s.Info.Counters = map[string]uint64{}
		}
	}
	return r.Status, err
}

func (c *Client) PfStates(req appliance.PfStatesRequest) (*appliance.PfStates, error) {
	var r PfStatesReply
	err := c.call("PfStates", req, &r)
	if s := r.States; s != nil {
		s.States = nonNil(s.States)
	}
	return r.States, err
}

func (c *Client) KillState(req appliance.KillStateRequest) error {
	return c.call("KillState", req, &EmptyReply{})
}

func (c *Client) RuleCounters() (*appliance.RuleCounters, error) {
	var r RuleCountersReply
	err := c.call("RuleCounters", None{}, &r)
	if s := r.Counters; s != nil && s.Labels == nil {
		s.Labels = map[string]appliance.RuleCounter{}
	}
	return r.Counters, err
}

func (c *Client) FirewallLog() (*appliance.FirewallLog, error) {
	var r FirewallLogReply
	err := c.call("FirewallLog", None{}, &r)
	if s := r.Log; s != nil {
		s.Entries = nonNil(s.Entries)
	}
	return r.Log, err
}

func (c *Client) StartTool(req diag.Request) (*diag.Run, error) {
	var r ToolRunReply
	err := c.call("StartTool", req, &r)
	if r.Run != nil {
		r.Run.Lines = nonNil(r.Run.Lines)
	}
	return r.Run, err
}

func (c *Client) ToolRun(id string, from int) (*diag.Run, error) {
	var r ToolRunReply
	err := c.call("ToolRun", ToolRunArgs{id, from}, &r)
	if r.Run != nil {
		r.Run.Lines = nonNil(r.Run.Lines)
	}
	return r.Run, err
}

func (c *Client) CancelTool(id string) error {
	return c.call("CancelTool", IDArgs{id}, &EmptyReply{})
}

func (c *Client) Tables() ([]appliance.TableStatus, error) {
	var r TablesReply
	err := c.call("Tables", None{}, &r)
	return nonNil(r.Tables), err
}

func (c *Client) RefreshAlias(name string) (*appliance.TableStatus, error) {
	var r TableReply
	err := c.call("RefreshAlias", NameArgs{name}, &r)
	return r.Table, err
}

func (c *Client) DNSLists() ([]appliance.DNSListStatus, error) {
	var r DNSListsReply
	err := c.call("DNSLists", None{}, &r)
	return nonNil(r.Lists), err
}

func (c *Client) RefreshDNSList(id string) (*appliance.DNSListStatus, error) {
	var r DNSListReply
	err := c.call("RefreshDNSList", IDArgs{id}, &r)
	return r.List, err
}

func (c *Client) Webhooks() ([]appliance.WebhookStatus, error) {
	var r WebhooksReply
	err := c.call("Webhooks", None{}, &r)
	return nonNil(r.Webhooks), err
}

func (c *Client) SetWebhookSecret(id string, req appliance.WebhookSecretRequest) (*appliance.WebhookSecretResult, error) {
	var r WebhookSecretReply
	err := c.call("SetWebhookSecret", WebhookSecretArgs{id, req}, &r)
	return r.Secret, err
}

func (c *Client) TestWebhook(id string) (*appliance.WebhookStatus, error) {
	var r WebhookReply
	err := c.call("TestWebhook", IDArgs{id}, &r)
	return r.Webhook, err
}

func (c *Client) DNSTool(req appliance.DNSToolRequest) (*appliance.DNSToolResult, error) {
	var r DNSToolReply
	err := c.call("DNSTool", req, &r)
	if t := r.Output; t != nil {
		t.Lines = nonNil(t.Lines)
	}
	return r.Output, err
}

func (c *Client) SystemLog(req appliance.SystemLogRequest) (*appliance.SystemLog, error) {
	var r SystemLogReply
	err := c.call("SystemLog", req, &r)
	if l := r.Log; l != nil {
		l.Lines, l.Programs = nonNil(l.Lines), nonNil(l.Programs)
	}
	return r.Log, err
}

func (c *Client) Events(req appliance.EventsRequest) (*appliance.Events, error) {
	var r EventsReply
	err := c.call("Events", req, &r)
	if e := r.Events; e != nil {
		e.Events = nonNil(e.Events)
	}
	return r.Events, err
}

func (c *Client) Metrics(req appliance.MetricsRequest) (*appliance.Metrics, error) {
	var r MetricsReply
	err := c.call("Metrics", req, &r)
	if m := r.Metrics; m != nil {
		m.Known = nonNil(m.Known)
		m.Groups = nonNil(m.Groups)
		if m.Series == nil {
			m.Series = map[string]*metrics.Result{}
		}
	}
	return r.Metrics, err
}

func (c *Client) DNSStats() (*appliance.DNSStats, error) {
	var r DNSStatsReply
	err := c.call("DNSStats", None{}, &r)
	if s := r.Stats; s != nil {
		s.Errors = nonNil(s.Errors)
	}
	return r.Stats, err
}

func (c *Client) DNSBlocked() (*appliance.DNSBlocked, error) {
	var r DNSBlockedReply
	err := c.call("DNSBlocked", None{}, &r)
	if b := r.Blocked; b != nil {
		b.Names = nonNil(b.Names)
		if b.ByList == nil {
			b.ByList = map[string]int{}
		}
	}
	return r.Blocked, err
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
