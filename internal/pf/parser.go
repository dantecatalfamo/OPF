package pf

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser converts pf.conf syntax to model types.
type Parser struct {
	tokens []Token
	pos    int
	model  *Model // for resolving macros and aliases
	errors []ParseError
}

// NewParser creates a parser for the given tokens.
func NewParser(tokens []Token, model *Model) *Parser {
	return &Parser{
		tokens: tokens,
		pos:    0,
		model:  model,
		errors: nil,
	}
}

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) peekN(n int) Token {
	if p.pos+n >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos+n]
}

func (p *Parser) advance() Token {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *Parser) check(types ...TokenType) bool {
	t := p.peek().Type
	for _, typ := range types {
		if t == typ {
			return true
		}
	}
	return false
}

func (p *Parser) checkKeyword(keywords ...string) bool {
	if p.peek().Type != TokenKeyword {
		return false
	}
	v := p.peek().Value
	for _, kw := range keywords {
		if v == kw {
			return true
		}
	}
	return false
}

func (p *Parser) expect(types ...TokenType) (Token, bool) {
	if p.check(types...) {
		return p.advance(), true
	}
	return Token{}, false
}

func (p *Parser) expectKeyword(keywords ...string) (Token, bool) {
	if p.checkKeyword(keywords...) {
		return p.advance(), true
	}
	return Token{}, false
}

func (p *Parser) error(msg string) {
	tok := p.peek()
	p.errors = append(p.errors, ParseError{
		Line:    tok.Line,
		Column:  tok.Column,
		Message: msg,
	})
}

func (p *Parser) skipToNextLine() {
	for !p.check(TokenNewline, TokenEOF) {
		p.advance()
	}
	if p.check(TokenNewline) {
		p.advance()
	}
}

// ParseRule parses a single pf rule from text.
func ParseRule(line string, model *Model) (*Rule, error) {
	tokens := Tokenize(line)
	p := NewParser(tokens, model)
	rule := p.parseRule()
	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parse error at line %d, column %d: %s",
			p.errors[0].Line, p.errors[0].Column, p.errors[0].Message)
	}
	return rule, nil
}

// ParsePfConf parses a full pf.conf file.
func ParsePfConf(content string, model *Model) *ParseResult {
	tokens := Tokenize(content)
	p := NewParser(tokens, model)

	result := &ParseResult{
		Rules:    []Rule{},
		Errors:   []ParseError{},
		Warnings: []Warning{},
	}

	for !p.check(TokenEOF) {
		// Skip blank lines
		if p.check(TokenNewline) {
			p.advance()
			continue
		}

		rule := p.parseRule()
		if rule != nil {
			result.Rules = append(result.Rules, *rule)
		}

		// Skip to next line if we haven't already
		if !p.check(TokenNewline, TokenEOF) {
			p.skipToNextLine()
		} else if p.check(TokenNewline) {
			p.advance()
		}
	}

	result.Errors = p.errors
	return result
}

// parseRule attempts to parse a rule starting at current position.
// Returns nil for lines that aren't rules (comments, set directives, etc).
func (p *Parser) parseRule() *Rule {
	// Check for supported rule types
	if !p.checkKeyword("pass", "block", "match") {
		// Not a filter rule - check for other directives
		if p.checkKeyword("set", "table", "anchor", "queue", "antispoof") {
			return p.parseAsRaw()
		}
		return nil
	}

	// Try to parse as a FormRule
	rule, ok := p.tryParseFormRule()
	if ok {
		return rule
	}

	// Fall back to RawRule
	return p.parseAsRaw()
}

// tryParseFormRule attempts to parse a FormRule. Returns (rule, true) on
// success, (nil, false) if this should be a RawRule instead.
func (p *Parser) tryParseFormRule() (*Rule, bool) {
	startPos := p.pos
	rule := &Rule{
		Kind:        "form",
		Enabled:     true,
		Interfaces:  []string{},
		Action:      ActionPass,
		Direction:   DirectionAny,
		Quick:       false,
		Family:      FamilyAny,
		Protocol:    ProtoAny,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Log:         LogOff,
	}

	// Action: pass | block [return[-rst|-icmp|-icmp6]] | match
	if tok, ok := p.expectKeyword("pass", "block", "match"); ok {
		switch tok.Value {
		case "pass":
			rule.Action = ActionPass
		case "block":
			rule.Action = ActionBlock
			// Check for return type
			if p.checkKeyword("return") {
				p.advance()
				rule.Action = ActionReject
			} else if p.checkKeyword("return-rst") {
				p.advance()
				rule.BlockReturn = BlockReturnRST
				// Check for ttl
				if p.checkKeyword("ttl") {
					p.advance()
					if tok, ok := p.expect(TokenNumber); ok {
						if n, err := strconv.Atoi(tok.Value); err == nil {
							rule.ReturnRstTTL = &n
						}
					}
				}
			} else if p.checkKeyword("return-icmp") {
				p.advance()
				rule.BlockReturn = BlockReturnICMP
				// Check for (code)
				if p.check(TokenLParen) {
					p.advance()
					if tok, ok := p.expect(TokenIdent, TokenNumber); ok {
						rule.ReturnICMPCode = tok.Value
					}
					p.expect(TokenRParen)
				}
			} else if p.checkKeyword("return-icmp6") {
				p.advance()
				rule.BlockReturn = BlockReturnICMP6
				if p.check(TokenLParen) {
					p.advance()
					if tok, ok := p.expect(TokenIdent, TokenNumber); ok {
						rule.ReturnICMPCode = tok.Value
					}
					p.expect(TokenRParen)
				}
			}
		case "match":
			rule.Action = ActionMatch
		}
	} else {
		p.pos = startPos
		return nil, false
	}

	// Direction: in | out (optional)
	if p.checkKeyword("in") {
		p.advance()
		rule.Direction = DirectionIn
	} else if p.checkKeyword("out") {
		p.advance()
		rule.Direction = DirectionOut
	}

	// Log: log [(all)]
	if p.checkKeyword("log") {
		p.advance()
		rule.Log = LogOn
		if p.check(TokenLParen) {
			p.advance()
			if p.checkKeyword("all") {
				p.advance()
				rule.Log = LogAll
			}
			p.expect(TokenRParen)
		}
	}

	// Quick
	if p.checkKeyword("quick") {
		p.advance()
		rule.Quick = true
	}

	// On: on <interface(s)>
	if p.checkKeyword("on") {
		p.advance()
		ifaces := p.parseInterfaceList()
		rule.Interfaces = ifaces
	}

	// Address family: inet | inet6
	if p.checkKeyword("inet") {
		p.advance()
		rule.Family = FamilyInet
	} else if p.checkKeyword("inet6") {
		p.advance()
		rule.Family = FamilyInet6
	}

	// Protocol
	if p.checkKeyword("proto") {
		p.advance()
		proto, ok := p.parseProtocol()
		if ok {
			rule.Protocol = proto
		}
	}

	// Source and destination
	if p.checkKeyword("all") {
		p.advance()
		// all means from any to any
	} else {
		// From
		if p.checkKeyword("from") {
			p.advance()
			endpoint, port, ok := p.parseEndpointWithPort()
			if ok {
				rule.Source = endpoint
				if port != "" {
					rule.SourcePort = port
				}
			}
			// OS fingerprint
			if p.checkKeyword("os") {
				p.advance()
				if tok, ok := p.expect(TokenString); ok {
					rule.OSFingerprint = tok.Value
				}
			}
		}

		// To
		if p.checkKeyword("to") {
			p.advance()
			endpoint, port, ok := p.parseEndpointWithPort()
			if ok {
				rule.Destination = endpoint
				if port != "" {
					rule.Port = port
				}
			}
		}
	}

	// Parse remaining options in a loop since they can appear in various orders
	for !p.check(TokenNewline, TokenEOF) {
		matched := false

		// TCP Flags
		if p.checkKeyword("flags") {
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
				flags := tok.Value
				if p.check(TokenSlash) {
					p.advance()
					if tok2, ok := p.expect(TokenIdent, TokenKeyword); ok {
						flags += "/" + tok2.Value
					}
				}
				rule.TCPFlags = flags
			}
			matched = true
		}

		// ICMP type
		if p.checkKeyword("icmp-type", "icmp6-type") {
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword, TokenNumber); ok {
				rule.ICMPType = tok.Value
			}
			matched = true
		}

		// Tagged
		if p.checkKeyword("tagged") {
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
				rule.Tagged = tok.Value
			}
			matched = true
		}

		// Tag
		if p.checkKeyword("tag") {
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
				rule.Tag = tok.Value
			}
			matched = true
		}

		// Probability
		if p.checkKeyword("probability") {
			p.advance()
			if tok, ok := p.expect(TokenNumber); ok {
				val := tok.Value
				// Remove % if present
				val = strings.TrimSuffix(val, "%")
				if n, err := strconv.Atoi(val); err == nil {
					rule.Probability = &n
				}
			}
			// Skip % token if separate
			if p.peek().Value == "%" {
				p.advance()
			}
			matched = true
		}

		// Once
		if p.checkKeyword("once") {
			p.advance()
			rule.Once = true
			matched = true
		}

		// State options: keep state | modulate state | synproxy state | no state
		if p.checkKeyword("keep", "modulate", "synproxy", "no") {
			state, ok := p.parseStateOptions()
			if ok && rule.Action == ActionPass {
				rule.State = state
			}
			matched = true
		}

		// Set options: set prio N
		if p.checkKeyword("set") {
			p.advance()
			if p.checkKeyword("prio") {
				p.advance()
				if tok, ok := p.expect(TokenNumber); ok {
					if n, err := strconv.Atoi(tok.Value); err == nil {
						rule.Prio = &n
					}
				}
			}
			matched = true
		}

		// Rtable
		if p.checkKeyword("rtable") {
			p.advance()
			if tok, ok := p.expect(TokenNumber); ok {
				if n, err := strconv.Atoi(tok.Value); err == nil {
					rule.RTable = &n
				}
			}
			matched = true
		}

		// Route-to
		if p.checkKeyword("route-to") {
			p.advance()
			// This is complex - we'd need to resolve gateway
			// For now, skip to next token
			p.advance()
			matched = true
		}

		// Reply-to
		if p.checkKeyword("reply-to") {
			p.advance()
			p.advance()
			matched = true
		}

		// NAT/redirect options (not supported in FormRule)
		if p.checkKeyword("nat-to", "rdr-to", "binat-to", "af-to", "divert-to") {
			p.pos = startPos
			return nil, false
		}

		// Label (description)
		if p.checkKeyword("label") {
			p.advance()
			if tok, ok := p.expect(TokenString); ok {
				rule.Description = tok.Value
			}
			matched = true
		}

		// If nothing matched, skip the token to avoid infinite loop
		if !matched {
			p.advance()
		}
	}

	return rule, true
}

// parseAsRaw captures the rest of the line as a RawRule.
func (p *Parser) parseAsRaw() *Rule {
	startPos := p.pos
	// Find line start in original tokens to capture full text
	var parts []string
	for !p.check(TokenNewline, TokenEOF) {
		tok := p.advance()
		switch tok.Type {
		case TokenString:
			parts = append(parts, fmt.Sprintf("%q", tok.Value))
		case TokenMacro:
			parts = append(parts, "$"+tok.Value)
		case TokenTable:
			parts = append(parts, "<"+tok.Value+">")
		default:
			parts = append(parts, tok.Value)
		}
	}

	if len(parts) == 0 {
		return nil
	}

	// Reconstruct the line
	text := strings.Join(parts, " ")

	// Check for description in label
	var desc string
	for i := startPos; i < p.pos; i++ {
		if p.tokens[i].Type == TokenKeyword && p.tokens[i].Value == "label" {
			if i+1 < p.pos && p.tokens[i+1].Type == TokenString {
				desc = p.tokens[i+1].Value
				break
			}
		}
	}

	return &Rule{
		Kind:        "raw",
		Enabled:     true,
		Interfaces:  []string{},
		Text:        text,
		Description: desc,
	}
}

func (p *Parser) parseInterfaceList() []string {
	var ifaces []string

	if p.check(TokenLBrace) {
		p.advance()
		for !p.check(TokenRBrace, TokenEOF) {
			iface := p.parseInterfaceRef()
			if iface != "" {
				ifaces = append(ifaces, iface)
			}
			// Skip comma
			if p.check(TokenComma) {
				p.advance()
			}
		}
		p.expect(TokenRBrace)
	} else {
		iface := p.parseInterfaceRef()
		if iface != "" {
			ifaces = append(ifaces, iface)
		}
	}

	return ifaces
}

func (p *Parser) parseInterfaceRef() string {
	if tok, ok := p.expect(TokenMacro); ok {
		return tok.Value
	}
	if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
		// Could be "egress" or a device name
		return tok.Value
	}
	return ""
}

func (p *Parser) parseProtocol() (Protocol, bool) {
	if p.check(TokenLBrace) {
		p.advance()
		var protos []string
		for !p.check(TokenRBrace, TokenEOF) {
			if tok, ok := p.expect(TokenKeyword, TokenIdent); ok {
				protos = append(protos, tok.Value)
			}
		}
		p.expect(TokenRBrace)
		// Check for tcp/udp combo
		if len(protos) == 2 {
			if (protos[0] == "tcp" && protos[1] == "udp") ||
				(protos[0] == "udp" && protos[1] == "tcp") {
				return ProtoTCPUDP, true
			}
		}
		// Return first for simplicity
		if len(protos) > 0 {
			return Protocol(protos[0]), true
		}
		return ProtoAny, false
	}

	if tok, ok := p.expect(TokenKeyword, TokenIdent); ok {
		switch tok.Value {
		case "tcp":
			return ProtoTCP, true
		case "udp":
			return ProtoUDP, true
		case "icmp":
			return ProtoICMP, true
		case "icmp6":
			return ProtoICMP6, true
		case "esp":
			return ProtoESP, true
		case "gre":
			return ProtoGRE, true
		}
	}
	return ProtoAny, false
}

func (p *Parser) parseEndpointWithPort() (Endpoint, string, bool) {
	endpoint := Endpoint{Type: EndpointAny}
	var port string

	// Check for negation
	negated := false
	if p.check(TokenBang) {
		p.advance()
		negated = true
	}

	// any
	if p.checkKeyword("any") {
		p.advance()
		endpoint = Endpoint{Type: EndpointAny, Not: negated}
		// Check for port after "any"
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// self
	if p.checkKeyword("self") {
		p.advance()
		endpoint = Endpoint{Type: EndpointSelf, Not: negated}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// Table: <name>
	if tok, ok := p.expect(TokenTable); ok {
		endpoint = Endpoint{Type: EndpointAlias, Alias: tok.Value, Not: negated}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// Macro: $name or ($name) or $name:network
	if p.check(TokenLParen) {
		p.advance()
		if tok, ok := p.expect(TokenMacro); ok {
			endpoint = Endpoint{Type: EndpointIfaddr, Iface: tok.Value, Not: negated}
			// Handle :0 suffix (used in NAT)
			if p.check(TokenColon) {
				p.advance()
				p.expect(TokenNumber) // consume the 0
			}
		}
		p.expect(TokenRParen)
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	if tok, ok := p.expect(TokenMacro); ok {
		// Check for :network suffix
		if p.check(TokenColon) {
			p.advance()
			if p.checkKeyword("network") {
				p.advance()
				endpoint = Endpoint{Type: EndpointNet, Iface: tok.Value, Not: negated}
			} else {
				// Unknown suffix, treat as ifaddr
				endpoint = Endpoint{Type: EndpointIfaddr, Iface: tok.Value, Not: negated}
			}
		} else {
			// Just a macro reference - could be an alias or interface
			// Default to interface address
			endpoint = Endpoint{Type: EndpointIfaddr, Iface: tok.Value, Not: negated}
		}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// IP address or CIDR
	if tok, ok := p.expect(TokenIPv4, TokenIPv6); ok {
		endpoint = Endpoint{Type: EndpointHost, Value: tok.Value, Not: negated}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	if tok, ok := p.expect(TokenCIDR); ok {
		endpoint = Endpoint{Type: EndpointNetwork, Value: tok.Value, Not: negated}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// Identifier (could be alias name or other)
	if tok, ok := p.expect(TokenIdent); ok {
		// Treat as alias
		endpoint = Endpoint{Type: EndpointAlias, Alias: tok.Value, Not: negated}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	return Endpoint{Type: EndpointAny}, "", false
}

func (p *Parser) parsePortSpec() string {
	// Port can be: number, range (n:m), list {n m ...}, or operator (> n, != n)
	if p.check(TokenLBrace) {
		p.advance()
		var ports []string
		for !p.check(TokenRBrace, TokenEOF) {
			if tok, ok := p.expect(TokenNumber, TokenIdent, TokenKeyword); ok {
				ports = append(ports, tok.Value)
			}
		}
		p.expect(TokenRBrace)
		return strings.Join(ports, ",")
	}

	// Operators: > >= < <= != = >< <>
	if p.check(TokenGT, TokenGTE, TokenLT, TokenLTE, TokenNE, TokenEQ) {
		op := p.advance().Value
		if tok, ok := p.expect(TokenNumber); ok {
			return op + " " + tok.Value
		}
		return ""
	}

	// Range operators: >< <>
	if p.check(TokenRange, TokenExclude) {
		// These need numbers on both sides: num >< num
		// But we might have already consumed the first number
		// This case is complex - skip for now
	}

	// Simple number or range
	if tok, ok := p.expect(TokenNumber); ok {
		return tok.Value
	}

	// Named port or alias
	if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
		return tok.Value
	}

	return ""
}

func (p *Parser) parseStateOptions() (*StateOptions, bool) {
	state := &StateOptions{Mode: StateModeKeep}

	// no state
	if p.checkKeyword("no") {
		p.advance()
		if p.checkKeyword("state") {
			p.advance()
			state.Mode = StateModeNone
			return state, true
		}
		return nil, false
	}

	// modulate state | synproxy state | keep state
	if p.checkKeyword("modulate") {
		p.advance()
		state.Mode = StateModeModulate
	} else if p.checkKeyword("synproxy") {
		p.advance()
		state.Mode = StateModeSynproxy
	} else if p.checkKeyword("keep") {
		p.advance()
		state.Mode = StateModeKeep
	} else {
		return nil, false
	}

	if !p.checkKeyword("state") {
		return nil, false
	}
	p.advance()

	// Parse state options in parentheses
	if p.check(TokenLParen) {
		p.advance()
		for !p.check(TokenRParen, TokenEOF) {
			if p.checkKeyword("max") {
				p.advance()
				if tok, ok := p.expect(TokenNumber); ok {
					if n, err := strconv.Atoi(tok.Value); err == nil {
						state.MaxStates = &n
					}
				}
			} else if p.checkKeyword("max-src-conn") {
				p.advance()
				if tok, ok := p.expect(TokenNumber); ok {
					if n, err := strconv.Atoi(tok.Value); err == nil {
						state.MaxSrcConn = &n
					}
				}
			} else if p.checkKeyword("max-src-conn-rate") {
				p.advance()
				// Format: count/seconds
				if tok, ok := p.expect(TokenNumber); ok {
					parts := strings.Split(tok.Value, "/")
					if len(parts) == 2 {
						count, _ := strconv.Atoi(parts[0])
						secs, _ := strconv.Atoi(parts[1])
						state.MaxSrcConnRate = &SrcConnRate{Count: count, Seconds: secs}
					} else {
						count, _ := strconv.Atoi(tok.Value)
						if p.check(TokenSlash) {
							p.advance()
							if tok2, ok := p.expect(TokenNumber); ok {
								secs, _ := strconv.Atoi(tok2.Value)
								state.MaxSrcConnRate = &SrcConnRate{Count: count, Seconds: secs}
							}
						}
					}
				}
			} else if p.checkKeyword("overload") {
				p.advance()
				if tok, ok := p.expect(TokenTable); ok {
					state.Overload = tok.Value
				}
				// Check for flush global
				if p.checkKeyword("flush") {
					p.advance()
					if p.checkKeyword("global") {
						p.advance()
						state.FlushGlobal = true
					}
				}
			} else if p.checkKeyword("sloppy") {
				p.advance()
				state.Sloppy = true
			} else if p.checkKeyword("if-bound") {
				p.advance()
				state.Policy = StatePolicyIfBound
			} else if p.checkKeyword("floating") {
				p.advance()
				state.Policy = StatePolicyFloating
			} else if p.check(TokenComma) {
				p.advance()
			} else {
				// Unknown option, skip
				p.advance()
			}
		}
		p.expect(TokenRParen)
	}

	return state, true
}
