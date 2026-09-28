package privsep

import (
	"fmt"
	"io"
	"log"
	"net/rpc"

	"github.com/dantecatalfamo/OPF/internal/appliance"
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
	srv.ServeConn(conn)
	close(svc.done)
}

// Client implements appliance.API by calling a Service.
type Client struct {
	rpc *rpc.Client
}

var _ appliance.API = (*Client)(nil)

func NewClient(conn io.ReadWriteCloser) *Client {
	return &Client{rpc: rpc.NewClient(conn)}
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
