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
	// Malformed says the lease had a statement Parse couldn't read,
	// which only a client's hostname can cause: it's Abandoned too, so
	// its address has no current lease.
	Malformed bool
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

// Parse reads a dhcpd.leases file.
//
// A client chooses its hostname, and dhcpd writes it into the file as
// it is, quotes and backslashes included (db.c refuses only bytes below
// 33 or above 126, so never a space or a newline). Parse reads the file
// the way dhcpd writes it, one statement a line, so what a client puts
// in its hostname can only spoil its own lease: a lease with anything
// it can't read is Malformed, and counts as no lease at all for its
// address. Statements it doesn't use are skipped. Only a file that ends
// inside a string or a lease is an error, so a half-written one is
// never mistaken for one with fewer leases.
func Parse(r io.Reader) ([]Lease, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("leases file is over %d bytes", maxFile)
	}
	p := &parser{lex: lexer{r: bufio.NewReader(bytes.NewReader(data)), line: 1, first: true}}
	var leases []Lease
	for {
		t, err := p.next()
		if err == io.EOF {
			return leases, nil
		} else if err != nil {
			return nil, err
		}
		switch {
		case t.kind == word && t.text == "lease":
			l, ok, err := p.lease(t)
			if err != nil {
				return nil, err
			}
			if ok {
				leases = append(leases, l)
			}
		case t.kind == punct && t.text == "}":
			// What's left of a lease whose line a client spoiled.
		default:
			// Some other top-level statement: skip it.
			if err := p.skip(t); err != nil {
				return nil, err
			}
		}
	}
}

type kind int

const (
	word kind = iota
	str
	punct // { } ;
	// bad is a string a line ended inside: dhcpd never writes one, so a
	// client's quote made it.
	bad
)

type token struct {
	kind kind
	text string
	line int
	// first says it's the first token on its line.
	first bool
}

type lexer struct {
	r     *bufio.Reader
	line  int
	first bool // the next token is the first on its line
}

func (l *lexer) next() (token, error) {
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return token{}, err
		}
		first := l.first
		switch {
		case c == '\n':
			l.line++
			l.first = true
			continue
		case c == ' ' || c == '\t' || c == '\r':
			continue
		case c == '#':
			for c != '\n' {
				if c, err = l.r.ReadByte(); err != nil {
					return token{}, err
				}
			}
			l.line++
			l.first = true
			continue
		}
		l.first = false
		switch {
		case c == '{' || c == '}' || c == ';':
			return token{punct, string(c), l.line, first}, nil
		case c == '"':
			t, err := l.quoted()
			t.first = first
			return t, err
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
			return token{word, b.String(), l.line, first}, nil
		}
	}
}

// quoted reads a string as dhcpd's read_string does (conflex.c): a
// backslash keeps the character after it, except a quote, which always
// ends the string. One a line ends inside is bad.
func (l *lexer) quoted() (token, error) {
	line := l.line
	var b strings.Builder
	escaped := false
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return token{}, fmt.Errorf("line %d: unterminated string", line)
		}
		switch {
		case c == '"':
			return token{kind: str, text: b.String(), line: line}, nil
		case c == '\n':
			l.line++
			l.first = true
			return token{kind: bad, line: line}, nil
		case escaped:
			escaped = false
			b.WriteByte(c)
		case c == '\\':
			escaped = true
		default:
			b.WriteByte(c)
		}
	}
}

type parser struct {
	lex  lexer
	back []token // tokens put back, read again first
}

func (p *parser) next() (token, error) {
	if n := len(p.back); n > 0 {
		t := p.back[n-1]
		p.back = p.back[:n-1]
		return t, nil
	}
	return p.lex.next()
}

// need reads a token, treating the end of the file as an error.
func (p *parser) need() (token, error) {
	t, err := p.next()
	if err == io.EOF {
		return t, fmt.Errorf("line %d: unexpected end of file", p.lex.line)
	}
	return t, err
}

// skip discards a top-level statement that started with t: up to its
// semicolon, or its block if it has one.
func (p *parser) skip(t token) error {
	depth := 0
	for {
		switch {
		case t.kind == punct && t.text == "{":
			depth++
		case t.kind == punct && t.text == "}":
			if depth--; depth <= 0 {
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

// lease reads a lease after its "lease" keyword, as dhcpd's write_lease
// writes it:
//
//	lease 192.168.1.112 {
//		starts 1 2026/09/28 10:00:00 UTC;
//		…
//	}
//
// The header is one line, each statement is one line, and the lease
// ends at a } alone at the start of a line. ok is false when the header
// isn't a lease's (it's skipped); a lease with a statement it can't
// read is returned Malformed.
func (p *parser) lease(kw token) (l Lease, ok bool, err error) {
	addr, err := p.need()
	if err != nil {
		return l, false, err
	}
	brace, err := p.need()
	if err != nil {
		return l, false, err
	}
	l.IP, err = netip.ParseAddr(addr.text)
	if addr.kind != word || err != nil || addr.line != kw.line || brace.kind != punct || brace.text != "{" || brace.line != kw.line {
		return l, false, p.skip(brace)
	}
	haveEnds := false
	for {
		t, err := p.need()
		if err != nil {
			return l, false, err
		}
		if t.kind == punct && t.text == "}" && t.first {
			break
		}
		if l.Malformed {
			continue // to the lease's closing brace
		}
		if t.kind != word || !t.first {
			l.Malformed = true
			continue
		}
		args, end, err := p.args(t.line)
		if err != nil {
			return l, false, err
		}
		if !end {
			l.Malformed = true
			continue
		}
		if !p.statement(&l, t.text, args, &haveEnds) {
			l.Malformed = true
		}
	}
	// A lease without an end isn't one dhcpd wrote; don't guess.
	if !haveEnds || l.Malformed {
		l.Abandoned = true
	}
	return l, true, nil
}

// args reads a statement's arguments up to its semicolon. end is false
// when the line doesn't hold exactly one statement: it ends first, or
// something follows the semicolon.
func (p *parser) args(line int) (out []token, end bool, err error) {
	for {
		t, err := p.need()
		if err != nil {
			return nil, false, err
		}
		if t.line != line {
			p.unread(t)
			return nil, false, nil
		}
		if t.kind == punct && t.text == ";" {
			// Nothing else may follow on the line.
			n, err := p.next()
			if err == io.EOF {
				return out, true, nil
			} else if err != nil {
				return nil, false, err
			}
			p.unread(n)
			return out, n.line != line, nil
		}
		if t.kind == punct || t.kind == bad {
			return nil, false, nil
		}
		out = append(out, t)
	}
}

// unread puts a token back to be read next.
func (p *parser) unread(t token) { p.back = append(p.back, t) }

// statement applies one statement of a lease; false if it's malformed.
func (p *parser) statement(l *Lease, name string, args []token, haveEnds *bool) bool {
	var err error
	switch name {
	case "starts":
		l.Starts, err = parseTime(args)
	case "ends":
		l.Ends, err = parseTime(args)
		*haveEnds = true
	case "hardware":
		if len(args) != 2 || args[0].kind != word || args[1].kind != word {
			return false
		}
		l.MAC = strings.ToLower(args[1].text)
	case "client-hostname":
		if len(args) != 1 || args[0].kind != str {
			return false
		}
		l.Hostname = args[0].text
	case "abandoned":
		l.Abandoned = true
	}
	return err == nil
}

// parseTime reads "never", or dhcpd's "<weekday> YYYY/MM/DD HH:MM:SS",
// in UTC, with or without a trailing "UTC".
func parseTime(args []token) (time.Time, error) {
	for _, a := range args {
		if a.kind != word {
			return time.Time{}, errors.New("a time is words, not a string")
		}
	}
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
