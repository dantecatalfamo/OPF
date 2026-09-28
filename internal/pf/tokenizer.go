package pf

import (
	"strings"
)

// TokenType identifies the kind of token.
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenError
	TokenKeyword // pass, block, match, in, out, on, proto, from, to, port, etc.
	TokenMacro   // $name
	TokenTable   // <name>
	TokenNumber  // 123, 8000:8080
	TokenIPv4    // 192.168.1.1
	TokenIPv6    // fe80::1
	TokenCIDR    // 192.168.1.0/24
	TokenString  // "quoted string"
	TokenIdent   // any identifier
	TokenLBrace  // {
	TokenRBrace  // }
	TokenLParen  // (
	TokenRParen  // )
	TokenComma   // ,
	TokenSlash   // /
	TokenColon   // :
	TokenBang    // !
	TokenLT      // <
	TokenGT      // >
	TokenLTE     // <=
	TokenGTE     // >=
	TokenNE      // !=
	TokenEQ      // =
	TokenRange   // ><
	TokenExclude // <>
	TokenNewline // end of logical line
)

var tokenNames = map[TokenType]string{
	TokenEOF:     "EOF",
	TokenError:   "Error",
	TokenKeyword: "Keyword",
	TokenMacro:   "Macro",
	TokenTable:   "Table",
	TokenNumber:  "Number",
	TokenIPv4:    "IPv4",
	TokenIPv6:    "IPv6",
	TokenCIDR:    "CIDR",
	TokenString:  "String",
	TokenIdent:   "Ident",
	TokenLBrace:  "LBrace",
	TokenRBrace:  "RBrace",
	TokenLParen:  "LParen",
	TokenRParen:  "RParen",
	TokenComma:   "Comma",
	TokenSlash:   "Slash",
	TokenColon:   "Colon",
	TokenBang:    "Bang",
	TokenLT:      "LT",
	TokenGT:      "GT",
	TokenLTE:     "LTE",
	TokenGTE:     "GTE",
	TokenNE:      "NE",
	TokenEQ:      "EQ",
	TokenRange:   "Range",
	TokenExclude: "Exclude",
	TokenNewline: "Newline",
}

func (t TokenType) String() string {
	if s, ok := tokenNames[t]; ok {
		return s
	}
	return "Unknown"
}

// Token is a single lexical token.
type Token struct {
	Type   TokenType
	Value  string
	Line   int
	Column int
}

// pf keywords. We recognize these but also allow them as identifiers
// in certain contexts (like alias names).
var keywords = map[string]bool{
	"pass": true, "block": true, "match": true,
	"in": true, "out": true, "on": true,
	"proto": true, "from": true, "to": true, "port": true,
	"quick": true, "log": true, "all": true,
	"flags": true, "keep": true, "modulate": true, "synproxy": true,
	"state": true, "no": true,
	"inet": true, "inet6": true,
	"icmp-type": true, "icmp6-type": true,
	"os": true, "tag": true, "tagged": true,
	"probability": true, "once": true,
	"set": true, "prio": true, "rtable": true,
	"route-to": true, "reply-to": true,
	"nat-to": true, "rdr-to": true, "binat-to": true,
	"af-to": true, "divert-to": true,
	"max": true, "max-src-conn": true, "max-src-conn-rate": true,
	"overload": true, "flush": true, "global": true,
	"sloppy": true, "if-bound": true, "floating": true,
	"any": true, "self": true, "return": true, "return-rst": true,
	"return-icmp": true, "return-icmp6": true,
	"tcp": true, "udp": true, "icmp": true, "icmp6": true,
	"esp": true, "gre": true,
	"anchor": true, "antispoof": true, "queue": true,
	"table": true, "const": true, "persist": true, "file": true,
	"label": true, "ttl": true,
	"scrub": true, "random-id": true, "no-df": true, "max-mss": true,
	"static-port": true, "round-robin": true, "source-hash": true,
	"network": true, "egress": true,
}

// Tokenizer performs lexical analysis of pf.conf syntax.
type Tokenizer struct {
	input   string
	pos     int
	line    int
	col     int
	linePos int // position of start of current line
}

// NewTokenizer creates a tokenizer for the given input.
func NewTokenizer(input string) *Tokenizer {
	return &Tokenizer{
		input: input,
		pos:   0,
		line:  1,
		col:   1,
	}
}

// The tokenizer works on bytes, like pf's own lexer (parse.y): bare
// words are ASCII, and other bytes only appear inside quoted strings,
// which are copied through unchanged. peek, peekN and advance return a
// byte widened to a rune; they never decode UTF-8.

func (t *Tokenizer) peek() rune {
	if t.pos >= len(t.input) {
		return 0
	}
	return rune(t.input[t.pos])
}

func (t *Tokenizer) peekN(n int) rune {
	if t.pos+n >= len(t.input) {
		return 0
	}
	return rune(t.input[t.pos+n])
}

func (t *Tokenizer) advance() rune {
	if t.pos >= len(t.input) {
		return 0
	}
	r := rune(t.input[t.pos])
	t.pos++
	if r == '\n' {
		t.line++
		t.col = 1
		t.linePos = t.pos
	} else {
		t.col++
	}
	return r
}

func (t *Tokenizer) skipWhitespace() {
	for {
		r := t.peek()
		if r == ' ' || r == '\t' {
			t.advance()
		} else if r == '\\' && t.peekN(1) == '\n' {
			// Line continuation
			t.advance() // skip \
			t.advance() // skip \n
		} else {
			break
		}
	}
}

func (t *Tokenizer) skipComment() {
	// Skip # to end of line
	for t.peek() != 0 && t.peek() != '\n' {
		t.advance()
	}
}

func (t *Tokenizer) token(typ TokenType, value string, startLine, startCol int) Token {
	return Token{Type: typ, Value: value, Line: startLine, Column: startCol}
}

// Next returns the next token.
func (t *Tokenizer) Next() Token {
	t.skipWhitespace()

	if t.pos >= len(t.input) {
		return Token{Type: TokenEOF, Line: t.line, Column: t.col}
	}

	startLine := t.line
	startCol := t.col
	r := t.peek()

	// Comment
	if r == '#' {
		t.skipComment()
		return t.Next()
	}

	// Newline
	if r == '\n' {
		t.advance()
		return t.token(TokenNewline, "\n", startLine, startCol)
	}

	// String
	if r == '"' {
		return t.scanString()
	}

	// Macro
	if r == '$' {
		return t.scanMacro()
	}

	// Table or comparison
	if r == '<' {
		t.advance()
		if t.peek() == '=' {
			t.advance()
			return t.token(TokenLTE, "<=", startLine, startCol)
		}
		if t.peek() == '>' {
			t.advance()
			return t.token(TokenExclude, "<>", startLine, startCol)
		}
		// Check if it's a table name
		if isIdentStart(t.peek()) {
			return t.scanTable(startLine, startCol)
		}
		return t.token(TokenLT, "<", startLine, startCol)
	}

	// Greater than
	if r == '>' {
		t.advance()
		if t.peek() == '=' {
			t.advance()
			return t.token(TokenGTE, ">=", startLine, startCol)
		}
		if t.peek() == '<' {
			t.advance()
			return t.token(TokenRange, "><", startLine, startCol)
		}
		return t.token(TokenGT, ">", startLine, startCol)
	}

	// Not equal or bang
	if r == '!' {
		t.advance()
		if t.peek() == '=' {
			t.advance()
			return t.token(TokenNE, "!=", startLine, startCol)
		}
		return t.token(TokenBang, "!", startLine, startCol)
	}

	// Equals
	if r == '=' {
		t.advance()
		return t.token(TokenEQ, "=", startLine, startCol)
	}

	// Single character tokens
	switch r {
	case '{':
		t.advance()
		return t.token(TokenLBrace, "{", startLine, startCol)
	case '}':
		t.advance()
		return t.token(TokenRBrace, "}", startLine, startCol)
	case '(':
		t.advance()
		return t.token(TokenLParen, "(", startLine, startCol)
	case ')':
		t.advance()
		return t.token(TokenRParen, ")", startLine, startCol)
	case ',':
		t.advance()
		return t.token(TokenComma, ",", startLine, startCol)
	case '/':
		t.advance()
		return t.token(TokenSlash, "/", startLine, startCol)
	case ':':
		t.advance()
		return t.token(TokenColon, ":", startLine, startCol)
	}

	// Numbers, IPs, and identifiers
	if isDigit(r) {
		return t.scanNumberOrIP()
	}

	if isIdentStart(r) {
		return t.scanIdent()
	}

	// Unknown byte
	start := t.pos
	t.advance()
	return t.token(TokenError, t.input[start:t.pos], startLine, startCol)
}

func (t *Tokenizer) scanString() Token {
	startLine := t.line
	startCol := t.col
	t.advance() // skip opening "
	var sb strings.Builder
	for {
		r := t.peek()
		if r == 0 || r == '\n' {
			return t.token(TokenError, "unterminated string", startLine, startCol)
		}
		if r == '"' {
			t.advance()
			break
		}
		if r == '\\' && t.peekN(1) != 0 {
			t.advance()
			r = t.peek()
		}
		sb.WriteByte(byte(r))
		t.advance()
	}
	return t.token(TokenString, sb.String(), startLine, startCol)
}

func (t *Tokenizer) scanMacro() Token {
	startLine := t.line
	startCol := t.col
	t.advance() // skip $
	var sb strings.Builder
	for isIdentChar(t.peek()) {
		sb.WriteByte(byte(t.advance()))
	}
	if sb.Len() == 0 {
		return t.token(TokenError, "empty macro name", startLine, startCol)
	}
	return t.token(TokenMacro, sb.String(), startLine, startCol)
}

func (t *Tokenizer) scanTable(startLine, startCol int) Token {
	var sb strings.Builder
	for {
		r := t.peek()
		if r == '>' {
			t.advance()
			break
		}
		if r == 0 || r == '\n' {
			return t.token(TokenError, "unterminated table name", startLine, startCol)
		}
		sb.WriteByte(byte(t.advance()))
	}
	return t.token(TokenTable, sb.String(), startLine, startCol)
}

func (t *Tokenizer) scanNumberOrIP() Token {
	startLine := t.line
	startCol := t.col
	startPos := t.pos

	// Collect all chars that could be part of a number/IP/CIDR
	var sb strings.Builder
	for {
		r := t.peek()
		if isDigit(r) || r == '.' || r == ':' || r == '/' ||
			(r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			sb.WriteByte(byte(t.advance()))
		} else {
			break
		}
	}

	val := sb.String()

	// Check for CIDR
	if strings.Contains(val, "/") {
		parts := strings.SplitN(val, "/", 2)
		if len(parts) == 2 && (isIPv4(parts[0]) || isIPv6(parts[0])) && isNumber(parts[1]) {
			return t.token(TokenCIDR, val, startLine, startCol)
		}
		// It's not a CIDR, might be a port range - backtrack
		t.pos = startPos
		t.col = startCol
		t.line = startLine
		return t.scanPlainNumber()
	}

	// Check for IPv4
	if isIPv4(val) {
		return t.token(TokenIPv4, val, startLine, startCol)
	}

	// Check for IPv6
	if isIPv6(val) {
		return t.token(TokenIPv6, val, startLine, startCol)
	}

	// Check for port range (8000:8080)
	if strings.Contains(val, ":") && !strings.Contains(val, "::") {
		parts := strings.SplitN(val, ":", 2)
		if isNumber(parts[0]) && isNumber(parts[1]) {
			return t.token(TokenNumber, val, startLine, startCol)
		}
	}

	// Plain number
	if isNumber(val) {
		return t.token(TokenNumber, val, startLine, startCol)
	}

	// Not recognized, treat as ident (rare edge case)
	return t.token(TokenIdent, val, startLine, startCol)
}

func (t *Tokenizer) scanPlainNumber() Token {
	startLine := t.line
	startCol := t.col
	var sb strings.Builder
	for isDigit(t.peek()) {
		sb.WriteByte(byte(t.advance()))
	}
	return t.token(TokenNumber, sb.String(), startLine, startCol)
}

func (t *Tokenizer) scanIdent() Token {
	startLine := t.line
	startCol := t.col
	startPos := t.pos
	var sb strings.Builder

	// Collect the full identifier, including potential IPv6 chars
	for {
		r := t.peek()
		if isIdentChar(r) || r == ':' {
			sb.WriteByte(byte(t.advance()))
		} else {
			break
		}
	}
	val := sb.String()

	// Check if it looks like an IPv6 address (contains :: or multiple colons)
	if strings.Contains(val, ":") && isIPv6(val) {
		return t.token(TokenIPv6, val, startLine, startCol)
	}

	// If it contains a colon but isn't IPv6, it might be macro:network
	// Split and return just the identifier part, then let the tokenizer
	// handle the colon separately
	if idx := strings.Index(val, ":"); idx > 0 && !strings.Contains(val, "::") {
		// Backtrack to before the colon. Identifiers are ASCII with no
		// newlines, so bytes, columns and characters line up.
		t.pos = startPos + idx
		t.col = startCol + idx
		val = val[:idx]
	}

	// Check if it's a keyword
	if keywords[val] || keywords[strings.ToLower(val)] {
		return t.token(TokenKeyword, strings.ToLower(val), startLine, startCol)
	}
	return t.token(TokenIdent, val, startLine, startCol)
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func isIdentStart(r rune) bool {
	return isLetter(r) || r == '_'
}

func isIdentChar(r rune) bool {
	return isLetter(r) || isDigit(r) || r == '_' || r == '-'
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(rune(s[i])) {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if !isNumber(p) {
			return false
		}
		n := 0
		for _, r := range p {
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	// Simple check - contains :: or multiple colons without dots
	if !strings.Contains(s, ":") {
		return false
	}
	if strings.Contains(s, ".") && !strings.Contains(s, "::") {
		return false // Mixed notation needs ::
	}

	// Must have hex chars and colons
	for _, r := range s {
		if !isDigit(r) && r != ':' &&
			!(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}

	// Check for valid IPv6 structure
	if strings.Contains(s, "::") {
		// Compressed notation
		parts := strings.Split(s, "::")
		if len(parts) > 2 {
			return false
		}
		return true
	}

	// Full notation: 8 groups
	parts := strings.Split(s, ":")
	return len(parts) == 8
}

// Tokenize returns all tokens from the input.
func Tokenize(input string) []Token {
	t := NewTokenizer(input)
	var tokens []Token
	for {
		tok := t.Next()
		tokens = append(tokens, tok)
		if tok.Type == TokenEOF {
			break
		}
	}
	return tokens
}
