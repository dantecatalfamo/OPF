package diag

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuild(t *testing.T) {
	for _, tc := range []struct {
		req  Request
		want string
	}{
		{Request{Tool: "ping", Host: "9.9.9.9"}, "ping -c 5 -s 56 -w 2 -- 9.9.9.9"},
		{Request{Tool: "ping", Host: " example.com ", Count: 3, Size: 1472, DontFragment: true}, "ping -c 3 -s 1472 -w 2 -D -- example.com"},
		{Request{Tool: "ping", Host: "2001:DB8::1"}, "ping6 -c 5 -s 56 -w 2 -- 2001:db8::1"},
		{Request{Tool: "ping", Host: "example.com", Family: "ipv6"}, "ping6 -c 5 -s 56 -w 2 -- example.com"},
		{Request{Tool: "ping", Host: "example.com", Family: "ipv4"}, "ping -c 5 -s 56 -w 2 -- example.com"},
		{Request{Tool: "traceroute", Host: "2620:fe::fe", Protocol: "icmp"}, "traceroute6 -I -n -m 30 -q 3 -w 2 -- 2620:fe::fe"},
		{Request{Tool: "traceroute", Host: "example.com"}, "traceroute -n -m 30 -q 3 -w 2 -- example.com"},
		{Request{Tool: "traceroute", Host: "1.1.1.1", Protocol: "icmp", ASNumbers: true, Names: true, MaxHops: 12}, "traceroute -I -A -m 12 -q 3 -w 2 -- 1.1.1.1"},
		{Request{Tool: "dns", Name: "example.com"}, "dig @127.0.0.1 -q example.com -t A +time=3 +tries=2"},
		{Request{Tool: "dns", Name: "_sip._tcp.example.com", Type: "srv", Server: "9.9.9.9", DNSSEC: true}, "dig @9.9.9.9 -q _sip._tcp.example.com -t SRV +time=3 +tries=2 +dnssec"},
		{Request{Tool: "dns", Name: "example.com", Type: "AAAA", Trace: true}, "dig -q example.com -t AAAA +time=3 +tries=2 +trace"},
		{Request{Tool: "dns", Name: "192.168.1.20"}, "dig @127.0.0.1 -x 192.168.1.20 +time=3 +tries=2"},
		{Request{Tool: "port", Host: "192.168.1.20", Port: 443}, "nc -4 -z -v -w 5 -- 192.168.1.20 443"},
		{Request{Tool: "port", Host: "ntp.example", Port: 123, Protocol: "udp"}, "nc -z -v -w 5 -u -- ntp.example 123"},
	} {
		argv, timeout, err := Build(tc.req)
		if err != nil {
			t.Errorf("%+v: %v", tc.req, err)
			continue
		}
		if got := strings.Join(argv, " "); got != tc.want {
			t.Errorf("%+v:\n got %s\nwant %s", tc.req, got, tc.want)
		}
		if timeout <= 0 || timeout > 3*time.Minute {
			t.Errorf("%+v: timeout %v", tc.req, timeout)
		}
	}
}

// Nothing a user types can become an option or reach a shell: every
// value is an address, a DNS name or a number, or it's refused.
func TestBuildRefuses(t *testing.T) {
	hostile := []string{
		"-f", "--help", "-c1000", "a b", "a;id", "a\nb", "a\x00b", "$(id)", "`id`", "a|b",
		"x\u202egnp.exe", "caf\u00e9.example", "-example.com", "example-.com", "a..b",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com", "fe80::1%em0", "",
	}
	for _, h := range hostile {
		for _, tool := range []string{"ping", "traceroute", "port"} {
			if _, _, err := Build(Request{Tool: tool, Host: h, Port: 80}); err == nil {
				t.Errorf("%s accepted host %q", tool, h)
			}
		}
		if _, _, err := Build(Request{Tool: "dns", Name: h}); err == nil {
			t.Errorf("dns accepted name %q", h)
		}
		if h != "" {
			if _, _, err := Build(Request{Tool: "dns", Name: "example.com", Server: h}); err == nil {
				t.Errorf("dns accepted server %q", h)
			}
		}
	}
	for _, r := range []Request{
		{Tool: "nope", Host: "a"},
		{Tool: "ping", Host: "a", Count: 51},
		{Tool: "ping", Host: "a", Count: -1},
		{Tool: "ping", Host: "a", Size: 9001},
		{Tool: "ping", Host: "::1", DontFragment: true},
		{Tool: "ping", Host: "::1", Family: "ipv4"},
		{Tool: "ping", Host: "a", Family: "ipx"},
		{Tool: "traceroute", Host: "a", Protocol: "tcp"},
		{Tool: "traceroute", Host: "a", MaxHops: 65},
		{Tool: "dns", Name: "a", Type: "A;id"},
		{Tool: "dns", Name: "a", Type: "AXFR"},
		{Tool: "port", Host: "a", Port: 0},
		{Tool: "port", Host: "a", Port: 65536},
		{Tool: "port", Host: "a", Port: 1, Protocol: "sctp"},
	} {
		if _, _, err := Build(r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	var inv *Invalid
	if _, _, err := Build(Request{Tool: "ping", Host: "a", Count: 99}); !errors.As(err, &inv) || inv.Field != "count" {
		t.Errorf("want an Invalid for count, got %v", err)
	}
}

// fake streams lines on a schedule and records what it ran.
type fake struct {
	mu    sync.Mutex
	ran   [][]string
	lines []string
	delay time.Duration
	err   error
}

func (f *fake) Run(ctx context.Context, argv ...string) ([]byte, error) {
	return []byte(strings.Join(f.lines, "\n")), f.err
}

func (f *fake) Stream(ctx context.Context, line func(string), argv ...string) error {
	f.mu.Lock()
	f.ran = append(f.ran, argv)
	f.mu.Unlock()
	for _, l := range f.lines {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.delay):
		}
		line(l)
	}
	return f.err
}

func wait(t *testing.T, rs *Runs, id string) *Run {
	t.Helper()
	for range 200 {
		r, err := rs.Get(id, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Running {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("still running")
	return nil
}

func TestRuns(t *testing.T) {
	f := &fake{lines: []string{"one", "t\two", "bad \u202e \x1b[2J \xff end"}, delay: time.Millisecond}
	rs := &Runs{Runner: f}
	r, err := rs.Start(Request{Tool: "ping", Host: "9.9.9.9"})
	if err != nil || !r.Running || r.Command != "ping -c 5 -s 56 -w 2 -- 9.9.9.9" {
		t.Fatalf("start: %+v %v", r, err)
	}
	done := wait(t, rs, r.ID)
	if done.ExitCode == nil || *done.ExitCode != 0 || len(done.Lines) != 3 || done.Next != 3 {
		t.Fatalf("done: %+v", done)
	}
	// Tabs stay; control characters, bidi overrides and bad UTF-8 go.
	if done.Lines[1] != "t\two" || done.Lines[2] != "bad \ufffd \ufffd[2J \ufffd end" {
		t.Errorf("lines: %q", done.Lines)
	}
	// Asking from a line gives the rest.
	if r, _ := rs.Get(r.ID, 2); r.From != 2 || len(r.Lines) != 1 {
		t.Errorf("from 2: %+v", r)
	}
	if r, _ := rs.Get(r.ID, 99); len(r.Lines) != 0 || r.Next != 3 {
		t.Errorf("from 99: %+v", r)
	}
	if _, err := rs.Get("nope", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := rs.Start(Request{Tool: "ping", Host: "-f"}); err == nil {
		t.Error("an invalid request started")
	}
}

func TestRunsLimits(t *testing.T) {
	slow := &fake{lines: []string{"a", "b", "c"}, delay: time.Hour}
	rs := &Runs{Runner: slow}
	var ids []string
	for range MaxRunning {
		r, err := rs.Start(Request{Tool: "ping", Host: "9.9.9.9"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if _, err := rs.Start(Request{Tool: "ping", Host: "9.9.9.9"}); !errors.Is(err, ErrBusy) {
		t.Errorf("one too many: %v", err)
	}
	for _, id := range ids {
		rs.Cancel(id)
		if r := wait(t, rs, id); r.Error != "stopped" {
			t.Errorf("cancelled: %+v", r)
		}
	}

	// Output past the limit stops the command.
	var many []string
	for i := range MaxLines + 10 {
		many = append(many, fmt.Sprint("line ", i))
	}
	rs = &Runs{Runner: &fake{lines: many}}
	r, _ := rs.Start(Request{Tool: "ping", Host: "9.9.9.9"})
	done := wait(t, rs, r.ID)
	if !done.Truncated || len(done.Lines) != MaxLines || !strings.Contains(done.Error, "more than") {
		t.Errorf("truncated: %d lines, %+v", len(done.Lines), done.Error)
	}

	// A command that fails reports its error.
	rs = &Runs{Runner: &fake{err: errors.New("exec: no such file")}}
	r, _ = rs.Start(Request{Tool: "ping", Host: "9.9.9.9"})
	if done := wait(t, rs, r.ID); done.Error == "" || done.ExitCode != nil {
		t.Errorf("failed: %+v", done)
	}
}

func TestExpire(t *testing.T) {
	rs := &Runs{Runner: &fake{}}
	r, _ := rs.Start(Request{Tool: "ping", Host: "9.9.9.9"})
	wait(t, rs, r.ID)
	rs.mu.Lock()
	rs.expire(time.Now().Add(Keep + time.Minute))
	_, kept := rs.jobs[r.ID]
	rs.mu.Unlock()
	if kept {
		t.Error("a run finished long ago was kept")
	}
}

type exitErr int

func (e exitErr) Error() string { return "exit status" }
func (e exitErr) ExitCode() int { return int(e) }

func TestExitCode(t *testing.T) {
	rs := &Runs{Runner: &fake{lines: []string{"no answer"}, err: exitErr(2)}}
	r, _ := rs.Start(Request{Tool: "ping", Host: "192.0.2.1"})
	if done := wait(t, rs, r.ID); done.ExitCode == nil || *done.ExitCode != 2 || done.Error != "" {
		t.Errorf("got %+v", done)
	}
}
