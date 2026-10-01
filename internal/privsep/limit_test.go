package privsep

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
)

type sample struct {
	Name string
	Data []byte
}

func encode(t *testing.T, values ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for _, v := range values {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestLimitReader(t *testing.T) {
	// Several messages, including gob's type definitions, pass through
	// unchanged.
	stream := encode(t, sample{"a", []byte("x")}, sample{"b", bytes.Repeat([]byte("y"), 500)}, 42, "done")
	dec := gob.NewDecoder(newLimitReader(bytes.NewReader(stream), 1000))
	var s sample
	var n int
	var str string
	if err := dec.Decode(&s); err != nil || s.Name != "a" {
		t.Fatalf("first: %+v, %v", s, err)
	}
	if err := dec.Decode(&s); err != nil || s.Name != "b" || len(s.Data) != 500 {
		t.Fatalf("second: %v", err)
	}
	if err := dec.Decode(&n); err != nil || n != 42 {
		t.Fatalf("third: %d, %v", n, err)
	}
	if err := dec.Decode(&str); err != nil || str != "done" {
		t.Fatalf("fourth: %q, %v", str, err)
	}
	if err := dec.Decode(&str); err != io.EOF {
		t.Errorf("at the end: %v, want EOF", err)
	}

	// A message over the limit is refused.
	stream = encode(t, sample{"big", bytes.Repeat([]byte("z"), 2000)})
	dec = gob.NewDecoder(newLimitReader(bytes.NewReader(stream), 1000))
	if err := dec.Decode(&s); !errors.Is(err, errTooBig) {
		t.Errorf("oversized message: %v, want errTooBig", err)
	}

	// A prefix claiming 1 GiB is refused from the prefix alone, before
	// anything would be allocated for it or read.
	forged := []byte{0xfc, 0x40, 0x00, 0x00, 0x00}
	dec = gob.NewDecoder(newLimitReader(bytes.NewReader(forged), 1000))
	if err := dec.Decode(&s); !errors.Is(err, errTooBig) {
		t.Errorf("forged prefix: %v, want errTooBig", err)
	}

	// Nonsense prefixes and truncated messages are errors, not hangs.
	for _, in := range [][]byte{{0xf0}, {0xfe, 0x01}, {0x05, 0x01}} {
		dec = gob.NewDecoder(newLimitReader(bytes.NewReader(in), 1000))
		if err := dec.Decode(&s); err == nil {
			t.Errorf("%x decoded", in)
		}
	}
}

// The web process can't make the root process take in a request bigger
// than maxMessage: the connection is dropped instead, and nothing is
// staged.
func TestRPCRefusesOversizedRequests(t *testing.T) {
	api := newAPI(t)
	a, b := net.Pipe()
	served := make(chan struct{})
	go func() { Serve(api, ServeOptions{Sessions: testSessions(t)}, a); close(served) }()
	c := signIn(t, NewClient(b), "admin")
	defer c.Close()

	live, err := c.Live()
	if err != nil {
		t.Fatal(err)
	}
	m := live.Model
	m.System.NTPServers = []string{strings.Repeat("x", maxMessage+1)}
	if _, err := c.Stage(appliance.StageRequest{Base: live.Version, Model: m}); err == nil {
		t.Fatal("an oversized request was accepted")
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the server kept the connection after an oversized request")
	}
	if _, err := api.Staged(); code(err) != appliance.CodeNothingStaged {
		t.Errorf("something was staged: %v", err)
	}
}

// Whatever the web process sends, the parent's decoder errors or
// decodes; it never panics, hangs, or takes a message over the limit.
func FuzzLimitReader(f *testing.F) {
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(sample{"seed", []byte("data")})
	f.Add(buf.Bytes())
	f.Add([]byte{0xfc, 0x40, 0x00, 0x00, 0x00})
	f.Add([]byte{0x81})
	f.Fuzz(func(t *testing.T, in []byte) {
		lr := newLimitReader(bytes.NewReader(in), 4096)
		dec := gob.NewDecoder(lr)
		for range 10 {
			var s sample
			if err := dec.Decode(&s); err != nil {
				return
			}
			if len(s.Data) > 4096 {
				t.Fatalf("decoded %d bytes through a 4096-byte limit", len(s.Data))
			}
		}
	})
}
