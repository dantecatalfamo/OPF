package diag

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dantecatalfamo/OPF/internal/run"
)

// Limits on runs, whatever is asked.
const (
	MaxRunning = 4                // runs at once, over every tool
	MaxLines   = 2000             // lines kept per run; the command is stopped past it
	MaxBytes   = 256 * 1024       // bytes kept per run, likewise
	Keep       = 15 * time.Minute // how long a finished run's output is kept
	MaxKept    = 50               // runs kept, finished or not
)

// Run is a run's state and the output from a line on.
type Run struct {
	ID      string    `json:"id"`
	Tool    string    `json:"tool"`
	Command string    `json:"command"` // the argv, for showing
	Started time.Time `json:"started"`
	// Running is false once it has ended; ExitCode is its exit status
	// when it ran to the end, and Error says why it didn't.
	Running  bool       `json:"running"`
	Finished *time.Time `json:"finished,omitempty"`
	ExitCode *int       `json:"exitCode,omitempty"`
	Error    string     `json:"error,omitempty"`
	// Lines are the output from line From on; Next is where to ask from
	// next time.
	From      int      `json:"from"`
	Lines     []string `json:"lines"`
	Next      int      `json:"next"`
	Truncated bool     `json:"truncated,omitempty"`
}

type job struct {
	Run
	lines  []string
	bytes  int
	cancel context.CancelFunc
}

// Runs runs tools and keeps their output.
type Runs struct {
	// Runner runs the commands; if it's also a run.Streamer, output
	// arrives line by line, otherwise all at once at the end.
	Runner run.Runner

	mu   sync.Mutex
	jobs map[string]*job
}

var (
	ErrBusy     = errors.New("too many tools are running; wait for one to finish")
	ErrNotFound = errors.New("no such run; its output is kept for 15 minutes")
)

// Start checks a request and starts it.
func (rs *Runs) Start(req Request) (*Run, error) {
	argv, timeout, err := Build(req)
	if err != nil {
		return nil, err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.expire(time.Now())
	running := 0
	for _, j := range rs.jobs {
		if j.Running {
			running++
		}
	}
	if running >= MaxRunning {
		return nil, ErrBusy
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	j := &job{Run: Run{ID: id, Tool: req.Tool, Command: strings.Join(argv, " "), Started: time.Now(), Running: true}, cancel: cancel}
	if rs.jobs == nil {
		rs.jobs = map[string]*job{}
	}
	rs.jobs[id] = j
	go rs.run(ctx, j, argv, timeout)
	r := rs.snapshot(j, 0)
	return &r, nil
}

func (rs *Runs) run(ctx context.Context, j *job, argv []string, timeout time.Duration) {
	defer j.cancel()
	line := func(l string) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		l = displayable(l)
		if len(j.lines) >= MaxLines || j.bytes+len(l) > MaxBytes {
			if !j.Truncated {
				j.Truncated = true
				j.cancel() // no one will see the rest
			}
			return
		}
		j.lines = append(j.lines, l)
		j.bytes += len(l)
	}
	var err error
	if s, ok := rs.Runner.(run.Streamer); ok {
		err = s.Stream(ctx, line, argv...)
	} else {
		var out []byte
		out, err = rs.Runner.Run(ctx, argv...)
		for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			if l != "" {
				line(l)
			}
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	now := time.Now()
	j.Running, j.Finished = false, &now
	// *exec.ExitError, or anything else that knows its exit status.
	var exit interface{ ExitCode() int }
	switch {
	case j.Truncated:
		j.Error = "stopped: it printed more than OPF keeps"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		j.Error = "stopped after " + timeout.String()
	case errors.Is(ctx.Err(), context.Canceled):
		j.Error = "stopped"
	case errors.As(err, &exit):
		code := exit.ExitCode()
		j.ExitCode = &code
	case err != nil:
		j.Error = err.Error()
	default:
		code := 0
		j.ExitCode = &code
	}
}

// Get returns a run with its output from line from on.
func (rs *Runs) Get(id string, from int) (*Run, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.expire(time.Now())
	j, ok := rs.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	r := rs.snapshot(j, from)
	return &r, nil
}

// Cancel stops a run.
func (rs *Runs) Cancel(id string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	j, ok := rs.jobs[id]
	if !ok {
		return ErrNotFound
	}
	j.cancel()
	return nil
}

func (rs *Runs) snapshot(j *job, from int) Run {
	r := j.Run
	from = max(0, min(from, len(j.lines)))
	r.From = from
	r.Lines = append([]string{}, j.lines[from:]...)
	r.Next = len(j.lines)
	return r
}

// expire forgets runs that finished long enough ago, and the oldest
// finished ones past MaxKept.
func (rs *Runs) expire(now time.Time) {
	var finished []*job
	for id, j := range rs.jobs {
		if j.Finished != nil && now.Sub(*j.Finished) > Keep {
			delete(rs.jobs, id)
			continue
		}
		if j.Finished != nil {
			finished = append(finished, j)
		}
	}
	for len(rs.jobs) >= MaxKept && len(finished) > 0 {
		oldest := 0
		for i, j := range finished {
			if j.Finished.Before(*finished[oldest].Finished) {
				oldest = i
			}
		}
		delete(rs.jobs, finished[oldest].ID)
		finished = append(finished[:oldest], finished[oldest+1:]...)
	}
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// displayable makes a line of output safe to show: tools print what
// the network sends them (DNS records, host names), so invalid UTF-8,
// control characters and bidi overrides become U+FFFD. Tabs stay; dig
// lines up its columns with them.
func displayable(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if !unicode.IsPrint(r) && r != ' ' || unicode.Is(unicode.Bidi_Control, r) {
			return '\uFFFD'
		}
		return r
	}, s)
}
