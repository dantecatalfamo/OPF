package privsep

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/rpc"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
)

// WireError carries an error across the socket without losing the
// details the UI needs: which sentinel it wraps, and the check or drift
// details.
type WireError struct {
	Kind   string
	Msg    string
	File   string
	Output string
	Files  []string
}

var sentinels = map[string]error{
	"unknown_file": config.ErrUnknownFile,
	"pending":      config.ErrPending,
	"no_pending":   config.ErrNoPending,
	"no_changes":   config.ErrNoChanges,
}

func encodeErr(err error) *WireError {
	if err == nil {
		return nil
	}
	w := &WireError{Kind: "other", Msg: err.Error()}
	var ce *config.CheckError
	var de *config.DriftError
	switch {
	case errors.As(err, &ce):
		w.Kind, w.File, w.Output = "check", ce.File, ce.Output
	case errors.As(err, &de):
		w.Kind, w.Files = "drift", de.Files
	default:
		for k, s := range sentinels {
			if errors.Is(err, s) {
				w.Kind = k
			}
		}
	}
	return w
}

// remoteError keeps the original message while still matching the
// sentinel with errors.Is.
type remoteError struct {
	msg string
	is  error
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.is }

func (w *WireError) decode() error {
	if w == nil {
		return nil
	}
	switch w.Kind {
	case "check":
		return &config.CheckError{File: w.File, Output: w.Output}
	case "drift":
		return &config.DriftError{Files: w.Files}
	}
	if s, ok := sentinels[w.Kind]; ok {
		return &remoteError{msg: w.Msg, is: s}
	}
	return errors.New(w.Msg)
}

// Every reply embeds Result so errors travel in-band; net/rpc would
// otherwise flatten them to strings.
type Result struct{ Err *WireError }

func (r *Result) remoteErr() error { return r.Err.decode() }

type (
	None        struct{}
	NameArgs    struct{ Name string }
	ContentArgs struct {
		Name string
		Data []byte
	}
	HistoryArgs struct {
		ID, Name string
		Old      bool
	}

	FilesReply struct {
		Result
		Files []config.File
	}
	ContentReply struct {
		Result
		Data []byte
		OK   bool
	}
	ChangesReply struct {
		Result
		Changes []config.Change
	}
	CheckReply struct {
		Result
		Output string
		OK     bool
	}
	EntryReply struct {
		Result
		Entry *config.Entry
	}
	HistoryReply struct {
		Result
		Entries []*config.Entry
	}
	TextReply struct {
		Result
		Text string
	}
	EmptyReply struct{ Result }
)

// commandTimeout bounds calls that run system commands. net/rpc has no
// way to carry the caller's context across.
const commandTimeout = 2 * time.Minute

// Service exposes a Store over net/rpc. It runs in the privileged
// process and trusts nothing but names and contents from the caller.
type Service struct {
	store *config.Store
	done  chan struct{} // closed when the connection ends
}

func (s *Service) Files(_ None, r *FilesReply) error {
	r.Files = s.store.Files()
	return nil
}

func (s *Service) Live(a NameArgs, r *ContentReply) error {
	var err error
	r.Data, r.OK, err = s.store.Live(a.Name)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Staged(a NameArgs, r *ContentReply) error {
	var err error
	r.Data, r.OK, err = s.store.Staged(a.Name)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Current(a NameArgs, r *ContentReply) error {
	var err error
	r.Data, err = s.store.Current(a.Name)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Stage(a ContentArgs, r *EmptyReply) error {
	r.Err = encodeErr(s.store.Stage(a.Name, a.Data))
	return nil
}

func (s *Service) Discard(a NameArgs, r *EmptyReply) error {
	r.Err = encodeErr(s.store.Discard(a.Name))
	return nil
}

func (s *Service) DiscardAll(_ None, r *EmptyReply) error {
	r.Err = encodeErr(s.store.DiscardAll())
	return nil
}

func (s *Service) Changes(_ None, r *ChangesReply) error {
	var err error
	r.Changes, err = s.store.Changes()
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) CheckContent(a ContentArgs, r *CheckReply) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	var err error
	r.Output, r.OK, err = s.store.CheckContent(ctx, a.Name, a.Data)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Commit(_ None, r *EntryReply) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	var err error
	r.Entry, err = s.store.Commit(ctx)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Pending(_ None, r *EntryReply) error {
	r.Entry = s.store.Pending()
	return nil
}

func (s *Service) Confirm(_ None, r *EmptyReply) error {
	r.Err = encodeErr(s.store.Confirm())
	return nil
}

func (s *Service) Revert(_ None, r *EmptyReply) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	r.Err = encodeErr(s.store.Revert(ctx))
	return nil
}

func (s *Service) History(_ None, r *HistoryReply) error {
	var err error
	r.Entries, err = s.store.History()
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) Entry(a HistoryArgs, r *EntryReply) error {
	var err error
	r.Entry, err = s.store.Entry(a.ID)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) EntryDiff(a HistoryArgs, r *TextReply) error {
	var err error
	r.Text, err = s.store.EntryDiff(a.ID, a.Name)
	r.Err = encodeErr(err)
	return nil
}

func (s *Service) StageFromHistory(a HistoryArgs, r *EmptyReply) error {
	r.Err = encodeErr(s.store.StageFromHistory(a.ID, a.Name, a.Old))
	return nil
}

// Wait doesn't return while the connection is up. The child calls it
// so that it notices, and exits, when the parent goes away.
func (s *Service) Wait(_ None, _ *None) error {
	<-s.done
	return errors.New("shutting down")
}

// Serve answers calls on conn until it is closed.
func Serve(store *config.Store, conn io.ReadWriteCloser) {
	srv := rpc.NewServer()
	svc := &Service{store: store, done: make(chan struct{})}
	if err := srv.RegisterName("OPF", svc); err != nil {
		panic(err) // only fails if Service's method set is malformed
	}
	srv.ServeConn(conn)
	close(svc.done)
}

// Client implements config.Manager by calling a Service.
type Client struct {
	rpc   *rpc.Client
	files []config.File
}

var _ config.Manager = (*Client)(nil)

func NewClient(conn io.ReadWriteCloser) (*Client, error) {
	c := &Client{rpc: rpc.NewClient(conn)}
	var r FilesReply
	if err := c.call("Files", None{}, &r); err != nil {
		return nil, err
	}
	c.files = r.Files
	return c, nil
}

func (c *Client) call(method string, args any, reply interface{ remoteErr() error }) error {
	if err := c.rpc.Call("OPF."+method, args, reply); err != nil {
		return fmt.Errorf("privileged process: %w", err)
	}
	return reply.remoteErr()
}

// Wait blocks until the connection to the parent is lost.
func (c *Client) Wait() error {
	return c.rpc.Call("OPF.Wait", None{}, &None{})
}

func (c *Client) Close() error { return c.rpc.Close() }

func (c *Client) Files() []config.File { return c.files }

func (c *Client) Live(name string) ([]byte, bool, error) {
	var r ContentReply
	err := c.call("Live", NameArgs{name}, &r)
	return r.Data, r.OK, err
}

func (c *Client) Staged(name string) ([]byte, bool, error) {
	var r ContentReply
	err := c.call("Staged", NameArgs{name}, &r)
	return r.Data, r.OK, err
}

func (c *Client) Current(name string) ([]byte, error) {
	var r ContentReply
	err := c.call("Current", NameArgs{name}, &r)
	return r.Data, err
}

func (c *Client) Stage(name string, data []byte) error {
	return c.call("Stage", ContentArgs{name, data}, &EmptyReply{})
}

func (c *Client) Discard(name string) error {
	return c.call("Discard", NameArgs{name}, &EmptyReply{})
}

func (c *Client) DiscardAll() error {
	return c.call("DiscardAll", None{}, &EmptyReply{})
}

func (c *Client) Changes() ([]config.Change, error) {
	var r ChangesReply
	err := c.call("Changes", None{}, &r)
	return r.Changes, err
}

func (c *Client) CheckContent(_ context.Context, name string, data []byte) (string, bool, error) {
	var r CheckReply
	err := c.call("CheckContent", ContentArgs{name, data}, &r)
	return r.Output, r.OK, err
}

func (c *Client) Commit(context.Context) (*config.Entry, error) {
	var r EntryReply
	err := c.call("Commit", None{}, &r)
	return r.Entry, err
}

// Pending returns nil if the parent can't be reached; the banner is the
// only caller and has nothing better to show.
func (c *Client) Pending() *config.Entry {
	var r EntryReply
	if err := c.call("Pending", None{}, &r); err != nil {
		return nil
	}
	return r.Entry
}

func (c *Client) Confirm() error {
	return c.call("Confirm", None{}, &EmptyReply{})
}

func (c *Client) Revert(context.Context) error {
	return c.call("Revert", None{}, &EmptyReply{})
}

func (c *Client) History() ([]*config.Entry, error) {
	var r HistoryReply
	err := c.call("History", None{}, &r)
	return r.Entries, err
}

func (c *Client) Entry(id string) (*config.Entry, error) {
	var r EntryReply
	err := c.call("Entry", HistoryArgs{ID: id}, &r)
	return r.Entry, err
}

func (c *Client) EntryDiff(id, name string) (string, error) {
	var r TextReply
	err := c.call("EntryDiff", HistoryArgs{ID: id, Name: name}, &r)
	return r.Text, err
}

func (c *Client) StageFromHistory(id, name string, old bool) error {
	return c.call("StageFromHistory", HistoryArgs{ID: id, Name: name, Old: old}, &EmptyReply{})
}
