// Package leases puts the names of dhcpd(8)'s clients into unbound(8).
//
// dhcpd records each lease in /var/db/dhcpd.leases with the hostname
// the client asked for. A Watcher reads that file and keeps an A record
// for each current lease in unbound's local data, through
// unbound-control(8), so devices can be reached by name without a
// reservation.
//
// Client hostnames are chosen by whoever is on the network, so they're
// treated as hostile: see Records for what a client can and can't
// claim.
package leases

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Path is where dhcpd keeps its leases.
const Path = "/var/db/dhcpd.leases"

// maxFile bounds the leases file. A few thousand leases are well under a
// megabyte.
const maxFile = 16 << 20

// Lease is one lease statement from dhcpd.leases(5).
type Lease struct {
	IP     netip.Addr
	Starts time.Time
	Ends   time.Time // zero if the lease never ends
	MAC    string
	// Hostname is what the client sent (client-hostname). Untrusted.
	Hostname  string
	Abandoned bool
}

// Active reports whether the lease is current at now.
func (l Lease) Active(now time.Time) bool {
	return !l.Abandoned && (l.Ends.IsZero() || now.Before(l.Ends))
}

// Read reads a leases file. A missing one has no leases: dhcpd hasn't
// run yet.
func Read(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	leases, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return leases, nil
}

// Current returns the leases in effect at now, one per address. dhcpd
// appends a new statement whenever a lease changes, so the last one for
// an address is the one that counts.
func Current(leases []Lease, now time.Time) []Lease {
	last := map[netip.Addr]int{}
	for i, l := range leases {
		last[l.IP] = i
	}
	var out []Lease
	for i, l := range leases {
		if last[l.IP] == i && l.Active(now) {
			out = append(out, l)
		}
	}
	return out
}

// Parse reads a dhcpd.leases file. Statements it doesn't use are
// skipped; anything malformed is an error, so a half-written or damaged
// file is never mistaken for one with fewer leases.
func Parse(r io.Reader) ([]Lease, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("leases file is over %d bytes", maxFile)
	}
	p := &parser{lex: lexer{r: bufio.NewReader(bytes.NewReader(data)), line: 1}}
	var leases []Lease
	for {
		t, err := p.next()
		if err == io.EOF {
			return leases, nil
		} else if err != nil {
			return nil, err
		}
		if t.kind == word && t.text == "lease" {
			l, err := p.lease()
			if err != nil {
				return nil, err
			}
			leases = append(leases, l)
			continue
		}
		// Some other top-level statement: skip it.
		if err := p.skip(t); err != nil {
			return nil, err
		}
	}
}

type kind int

const (
	word kind = iota
	str
	punct // { } ;
)

type token struct {
	kind kind
	text string
	line int
}

type lexer struct {
	r    *bufio.Reader
	line int
}

func (l *lexer) next() (token, error) {
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return token{}, err
		}
		switch {
		case c == '\n':
			l.line++
		case c == ' ' || c == '\t' || c == '\r':
		case c == '#':
			for c != '\n' {
				if c, err = l.r.ReadByte(); err != nil {
					return token{}, err
				}
			}
			l.line++
		case c == '{' || c == '}' || c == ';':
			return token{punct, string(c), l.line}, nil
		case c == '"':
			return l.quoted()
		default:
			var b strings.Builder
			b.WriteByte(c)
			for {
				c, err := l.r.ReadByte()
				if err == io.EOF {
					break
				} else if err != nil {
					return token{}, err
				}
				if strings.IndexByte(" \t\r\n{};\"#", c) >= 0 {
					l.r.UnreadByte()
					break
				}
				b.WriteByte(c)
			}
			return token{word, b.String(), l.line}, nil
		}
	}
}

func (l *lexer) quoted() (token, error) {
	line := l.line
	var b strings.Builder
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return token{}, fmt.Errorf("line %d: unterminated string", line)
		}
		switch c {
		case '"':
			return token{str, b.String(), line}, nil
		case '\\':
			if c, err = l.r.ReadByte(); err != nil {
				return token{}, fmt.Errorf("line %d: unterminated string", line)
			}
		case '\n':
			return token{}, fmt.Errorf("line %d: newline in string", line)
		}
		b.WriteByte(c)
	}
}

type parser struct {
	lex lexer
}

func (p *parser) next() (token, error) { return p.lex.next() }

// need reads a token, treating the end of the file as an error.
func (p *parser) need() (token, error) {
	t, err := p.next()
	if err == io.EOF {
		return t, fmt.Errorf("line %d: unexpected end of file", p.lex.line)
	}
	return t, err
}

// skip discards a statement that started with t: up to its semicolon,
// or its block if it has one.
func (p *parser) skip(t token) error {
	depth := 0
	for {
		switch {
		case t.kind == punct && t.text == "{":
			depth++
		case t.kind == punct && t.text == "}":
			depth--
			if depth < 0 {
				return fmt.Errorf("line %d: unexpected }", t.line)
			}
			if depth == 0 {
				return nil
			}
		case t.kind == punct && t.text == ";" && depth == 0:
			return nil
		}
		var err error
		if t, err = p.need(); err != nil {
			return err
		}
	}
}

// args reads a statement's arguments up to its semicolon.
func (p *parser) args() ([]token, error) {
	var out []token
	for {
		t, err := p.need()
		if err != nil {
			return nil, err
		}
		if t.kind == punct {
			if t.text == ";" {
				return out, nil
			}
			return nil, fmt.Errorf("line %d: unexpected %s", t.line, t.text)
		}
		out = append(out, t)
	}
}

func (p *parser) lease() (Lease, error) {
	var l Lease
	t, err := p.need()
	if err != nil {
		return l, err
	}
	if l.IP, err = netip.ParseAddr(t.text); t.kind != word || err != nil {
		return l, fmt.Errorf("line %d: lease for %q, not an address", t.line, t.text)
	}
	if t, err = p.need(); err != nil {
		return l, err
	}
	if t.kind != punct || t.text != "{" {
		return l, fmt.Errorf("line %d: expected { after lease %s", t.line, l.IP)
	}
	haveEnds := false
	for {
		t, err := p.need()
		if err != nil {
			return l, err
		}
		if t.kind == punct && t.text == "}" {
			break
		}
		if t.kind != word {
			return l, fmt.Errorf("line %d: unexpected %q in lease %s", t.line, t.text, l.IP)
		}
		args, err := p.args()
		if err != nil {
			return l, err
		}
		switch t.text {
		case "starts":
			if l.Starts, err = parseTime(args); err != nil {
				return l, fmt.Errorf("line %d: starts: %w", t.line, err)
			}
		case "ends":
			if l.Ends, err = parseTime(args); err != nil {
				return l, fmt.Errorf("line %d: ends: %w", t.line, err)
			}
			haveEnds = true
		case "hardware":
			if len(args) == 2 {
				l.MAC = strings.ToLower(args[1].text)
			}
		case "client-hostname":
			if len(args) != 1 || args[0].kind != str {
				return l, fmt.Errorf("line %d: client-hostname needs one string", t.line)
			}
			l.Hostname = args[0].text
		case "abandoned":
			l.Abandoned = true
		}
	}
	// A lease without an end isn't one dhcpd wrote; don't guess.
	if !haveEnds {
		l.Abandoned = true
	}
	return l, nil
}

// parseTime reads "never", or dhcpd's "<weekday> YYYY/MM/DD HH:MM:SS",
// in UTC, with or without a trailing "UTC".
func parseTime(args []token) (time.Time, error) {
	if len(args) == 1 && args[0].text == "never" {
		return time.Time{}, nil
	}
	if len(args) == 4 && args[3].text == "UTC" {
		args = args[:3]
	}
	if len(args) != 3 {
		return time.Time{}, errors.New("expected a weekday, date and time")
	}
	t, err := time.ParseInLocation("2006/01/02 15:04:05", args[1].text+" "+args[2].text, time.UTC)
	if err != nil {
		return time.Time{}, err
	}
	if t.IsZero() {
		return time.Time{}, errors.New("zero time")
	}
	return t, nil
}
