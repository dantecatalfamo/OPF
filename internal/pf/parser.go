package pf

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parser converts pf.conf syntax to model types.
type Parser struct {
	input  string // text the tokens' offsets refer to, when known
	tokens []Token
	pos    int
	model  *Model // for resolving macros and aliases
	errors []ParseError
	// notForm is set when part of a rule can't be represented as a
	// FormRule without losing meaning; the rule is kept as a RawRule.
	notForm bool
	// groups collects the current rule's non-model "on" entries.
	groups []string
}

// NewParser creates a parser for the given tokens.
// sourceText returns the input covering tokens[from:to], exactly as
// written apart from line continuations, which pf's lexer removes too
// (see tokenize). Rebuilding it from tokens would split "$lan:network"
// into "$lan : network", which pf rejects.
func (p *Parser) sourceText(from, to int) string {
	first, last := p.tokens[from], p.tokens[to-1]
	if p.input == "" || last.End > len(p.input) || first.Pos > last.End {
		// No source (a parser built directly from tokens): rebuild it.
		var parts []string
		for _, tok := range p.tokens[from:to] {
			parts = append(parts, tok.Value)
		}
		return strings.Join(parts, " ")
	}
	return p.input[first.Pos:last.End]
}

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

// expectString consumes a quoted string. A value the generator can't
// write back unchanged (one with a backslash or newline, or invalid
// UTF-8, which JSON would also mangle) keeps the rule raw.
func (p *Parser) expectString() (string, bool) {
	tok, ok := p.expect(TokenString)
	if !ok {
		return "", false
	}
	if strings.ContainsAny(tok.Value, "\\\n") || !utf8.ValidString(tok.Value) {
		p.notForm = true
	}
	return tok.Value, true
}

// expectInt consumes a plain decimal number.
func (p *Parser) expectInt() (int, bool) {
	tok, ok := p.expect(TokenNumber)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(tok.Value)
	return n, err == nil
}

// parseParenCode reads "code)" after "return-icmp(". Anything else,
// such as a second code for IPv6, keeps the rule raw.
func (p *Parser) parseParenCode() string {
	tok, ok := p.expect(TokenIdent, TokenKeyword, TokenNumber)
	if !ok {
		p.notForm = true
	}
	if _, ok := p.expect(TokenRParen); !ok {
		p.notForm = true
	}
	return tok.Value
}

// parseFlags reads "S/SA", "/SA" or "any" after "flags".
func (p *Parser) parseFlags() string {
	if _, ok := p.expectKeyword("any"); ok {
		return "any"
	}
	flags := ""
	if tok, ok := p.expect(TokenIdent); ok {
		flags = tok.Value
	}
	if _, ok := p.expect(TokenSlash); !ok {
		p.notForm = true
		return flags
	}
	tok, ok := p.expect(TokenIdent)
	if !ok {
		p.notForm = true
	}
	return flags + "/" + tok.Value
}

// parseGateway reads the address after route-to or reply-to and maps it
// to a gateway in the model. Other forms ("(em0 10.0.0.1)", pools,
// interface names) and addresses without a gateway keep the rule raw.
func (p *Parser) parseGateway() string {
	tok, ok := p.expect(TokenIPv4, TokenIPv6)
	if !ok {
		p.notForm = true
		return ""
	}
	if p.model != nil {
		for _, g := range p.model.Routing.Gateways {
			if gatewayAddr(g.ID, p.model) == tok.Value {
				return g.ID
			}
		}
	}
	p.notForm = true
	return ""
}

// parseIfaceRef reads an interface or group name, or self, and its modifiers
// (":network", ":broadcast", ":peer", ":0"). As in pfctl (parse.y
// dynaddr, pfctl_parser.c host_if), the three address modifiers are
// mutually exclusive and ":0" combines with any of them, in any order.
//
// Without parentheses a name is only certainly an interface when it
// carries :network, :broadcast or :peer, which host names can't; a bare
// name or one with only ":0" is accepted when it's a model interface
// and otherwise reported as not an interface (ok false).
func (p *Parser) parseIfaceRef(dynamic bool) (Endpoint, bool) {
	e := Endpoint{Type: EndpointIface, Dynamic: &dynamic}
	tok, ok := p.expect(TokenMacro, TokenIdent, TokenKeyword)
	if !ok {
		return e, false
	}
	modelIface := false
	switch {
	case tok.Type == TokenKeyword && tok.Value == "self":
		// Every address of this firewall; takes the same modifiers.
		e.Type = EndpointSelf
		modelIface = true // never a host name
	case tok.Type == TokenMacro:
		e.Iface = tok.Value
		if p.model != nil && !p.model.hasInterface(tok.Value) {
			p.notForm = true // a macro for something other than an interface
		}
		modelIface = true
	case p.model != nil && p.model.deviceID(tok.Value) != "":
		e.Iface = p.model.deviceID(tok.Value)
		modelIface = true
	default:
		e.Group = tok.Value
	}

	for p.check(TokenColon) {
		p.advance()
		var part IfacePart
		switch {
		case p.checkKeyword("network"):
			part = PartNetwork
		case p.peek().Type == TokenIdent && (p.peek().Value == "broadcast" || p.peek().Value == "peer"):
			part = IfacePart(p.peek().Value)
		case p.peek().Type == TokenNumber && p.peek().Value == "0":
			e.NoAlias = true
			p.advance()
			continue
		default:
			p.notForm = true // pfctl rejects other modifiers
			return e, true
		}
		p.advance()
		if e.Part != PartAddress && e.Part != part {
			p.notForm = true // "illegal combination of interface modifiers"
		}
		e.Part = part
	}

	if !dynamic && !modelIface && e.Part == PartAddress {
		// A bare name, or name:0: an interface if one exists at load
		// time, otherwise a host name. Can't tell which.
		if tok.Type == TokenMacro {
			return e, true
		}
		return e, false
	}
	if !dynamic && tok.Type == TokenMacro && e.Part == PartAddress && !e.NoAlias && p.model == nil {
		// A bare $macro could hold addresses rather than an interface.
		// With a model, a macro named after a model interface is the one
		// the generator defines for it, and anything else was rejected
		// above.
		p.notForm = true
	}
	return e, true
}

// parseBraceList reads the items of a "{ a b, c }" list, with the
// opening brace already consumed. Every iteration consumes a token or
// returns, so it always terminates. It fails, leaving the offending
// token unconsumed, on an empty list, on a token not in accept, or when
// the line ends before the closing brace, so a missing brace can't
// swallow the following lines.
func (p *Parser) parseBraceList(accept ...TokenType) ([]Token, bool) {
	var items []Token
	for {
		switch {
		case p.check(TokenRBrace):
			p.advance()
			// "{ }" is a syntax error in pf; accepting it would turn
			// "port { }" into "any port".
			return items, len(items) > 0
		case p.check(TokenComma):
			p.advance()
		case p.check(accept...):
			items = append(items, p.advance())
		default:
			return items, false
		}
	}
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
	tokens, joined := tokenize(line)
	p := NewParser(tokens, model)
	p.input = joined
	rule := p.parseRule()
	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parse error at line %d, column %d: %s",
			p.errors[0].Line, p.errors[0].Column, p.errors[0].Message)
	}
	return rule, nil
}

// ParsePfConf parses a full pf.conf file.
func ParsePfConf(content string, model *Model) *ParseResult {
	tokens, joined := tokenize(content)
	p := NewParser(tokens, model)
	p.input = joined

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

		start := p.pos
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
		if p.pos == start {
			// Can't happen with the code above; guarantees termination
			// if a future change breaks that.
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
					if n, ok := p.expectInt(); ok {
						rule.ReturnRstTTL = &n
					} else {
						p.notForm = true
					}
				}
			} else if p.checkKeyword("return-icmp") {
				p.advance()
				rule.BlockReturn = BlockReturnICMP
				// Check for (code)
				if p.check(TokenLParen) {
					p.advance()
					rule.ReturnICMPCode = p.parseParenCode()
				}
			} else if p.checkKeyword("return-icmp6") {
				p.advance()
				rule.BlockReturn = BlockReturnICMP6
				if p.check(TokenLParen) {
					p.advance()
					rule.ReturnICMPCode = p.parseParenCode()
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
			// Only "log (all)" is modelled; "(user)", "(matches)" and
			// "(to pflogN)" keep the rule raw.
			p.advance()
			if _, ok := p.expectKeyword("all"); ok {
				rule.Log = LogAll
			} else {
				p.notForm = true
			}
			if _, ok := p.expect(TokenRParen); !ok {
				p.notForm = true
			}
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
		p.groups = nil
		if ifaces := p.parseInterfaceList(); ifaces != nil {
			rule.Interfaces = ifaces // otherwise stays [], never JSON null
		}
		rule.Groups = p.groups
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
		} else {
			// A protocol the form can't express; treating it as
			// "any" would widen the rule.
			p.notForm = true
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
			} else {
				p.notForm = true
			}
			// OS fingerprint
			if p.checkKeyword("os") {
				p.advance()
				if v, ok := p.expectString(); ok {
					rule.OSFingerprint = v
				} else {
					p.notForm = true
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
			} else {
				p.notForm = true
			}
		}
	}

	// Parse remaining options in a loop since they can appear in various
	// orders. Anything not modelled here, a repeated option, or an
	// option whose argument can't be read makes the rule raw: skipping
	// it would silently change what the rule does.
	seen := map[string]bool{}
	for !p.check(TokenNewline, TokenEOF) {
		opt := p.peek().Value
		if p.peek().Type == TokenKeyword {
			if seen[opt] {
				p.notForm = true
			}
			seen[opt] = true
		}

		switch {
		case p.checkKeyword("flags"):
			p.advance()
			rule.TCPFlags = p.parseFlags()

		case p.checkKeyword("icmp-type", "icmp6-type"):
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword, TokenNumber); ok {
				rule.ICMPType = tok.Value
			} else {
				p.notForm = true
			}
			if (opt == "icmp6-type") != (rule.Protocol == ProtoICMP6) {
				p.notForm = true // the generator picks the keyword from the protocol
			}

		case p.checkKeyword("tagged"):
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
				rule.Tagged = tok.Value
			} else {
				p.notForm = true
			}

		case p.checkKeyword("tag"):
			p.advance()
			if tok, ok := p.expect(TokenIdent, TokenKeyword); ok {
				rule.Tag = tok.Value
			} else {
				p.notForm = true
			}

		case p.checkKeyword("probability"):
			p.advance()
			if n, ok := p.expectInt(); ok && n >= 0 && n <= 100 {
				rule.Probability = &n
			} else {
				p.notForm = true
			}
			// "50%" tokenizes as a number and a separate "%".
			if p.peek().Value == "%" {
				p.advance()
			}

		case p.checkKeyword("once"):
			p.advance()
			rule.Once = true

		case p.checkKeyword("keep", "modulate", "synproxy", "no"):
			state, ok := p.parseStateOptions()
			if !ok || rule.Action != ActionPass {
				// State only means something on pass rules, and only
				// pass rules get it back from the generator.
				p.notForm = true
			}
			if state != nil && *state == (StateOptions{Mode: StateModeKeep}) {
				// Plain "keep state" is pf's default for pass rules.
				state = nil
			}
			rule.State = state

		case p.checkKeyword("set"):
			p.advance()
			// Only "set prio N" is modelled; "set prio (N, M)",
			// "set tos" and "set queue" keep the rule raw.
			if _, ok := p.expectKeyword("prio"); !ok {
				p.notForm = true
				break
			}
			if n, ok := p.expectInt(); ok && n >= 0 && n <= 7 {
				rule.Prio = &n
			} else {
				p.notForm = true
			}

		case p.checkKeyword("rtable"):
			p.advance()
			if n, ok := p.expectInt(); ok {
				rule.RTable = &n
			} else {
				p.notForm = true
			}

		case p.checkKeyword("route-to", "reply-to"):
			p.advance()
			gw := p.parseGateway()
			if opt == "route-to" {
				rule.Gateway = gw
			} else {
				rule.ReplyTo = gw
			}

		case p.checkKeyword("nat-to", "rdr-to", "binat-to", "af-to", "divert-to"):
			// NAT/redirect options (not supported in FormRule)
			p.pos = startPos
			p.notForm = false
			return nil, false

		case p.checkKeyword("label"):
			// OPF's own label carries the rule's id. Any other label
			// can't be kept on a guided rule, whose label slot is
			// taken, so the rule stays raw.
			p.advance()
			v, ok := p.expectString()
			if kind, id, own := ParseLabel(v); ok && own && kind == LabelRule {
				rule.ID = id
			} else {
				p.notForm = true
			}

		default:
			p.notForm = true
			p.advance()
		}
	}

	// Combinations the generator can't write back.
	hasPorts := rule.Protocol == ProtoTCP || rule.Protocol == ProtoUDP || rule.Protocol == ProtoTCPUDP
	if (rule.Port != "" || rule.SourcePort != "") && !hasPorts {
		p.notForm = true
	}
	if rule.TCPFlags != "" && rule.Protocol != ProtoTCP && rule.Protocol != ProtoTCPUDP {
		p.notForm = true
	}
	if rule.ICMPType != "" && rule.Protocol != ProtoICMP && rule.Protocol != ProtoICMP6 {
		p.notForm = true
	}
	if rule.BlockReturn != "" && rule.Action != ActionBlock {
		p.notForm = true
	}

	if p.notForm {
		p.notForm = false
		p.pos = startPos
		return nil, false
	}
	return rule, true
}

// parseAsRaw captures the rest of the line as a RawRule.
func (p *Parser) parseAsRaw() *Rule {
	startPos := p.pos
	for !p.check(TokenNewline, TokenEOF) {
		p.advance()
	}
	if p.pos == startPos {
		return nil
	}
	text := p.sourceText(startPos, p.pos)

	// A label written by hand is the best description there is. The
	// text keeps it either way.
	var desc string
	for i := startPos; i < p.pos; i++ {
		if p.tokens[i].Type == TokenKeyword && p.tokens[i].Value == "label" {
			if i+1 < p.pos && p.tokens[i+1].Type == TokenString {
				if _, _, own := ParseLabel(p.tokens[i+1].Value); !own {
					desc = p.tokens[i+1].Value
				}
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
		items, ok := p.parseBraceList(TokenMacro, TokenIdent, TokenKeyword)
		if !ok {
			p.notForm = true
		}
		for _, tok := range items {
			p.addInterface(tok, &ifaces)
		}
	} else if tok, ok := p.expect(TokenMacro, TokenIdent, TokenKeyword); ok {
		p.addInterface(tok, &ifaces)
	} else {
		p.notForm = true // "on ! em0" and the like
	}

	return ifaces
}

// addInterface records an "on" clause entry: a macro or a device in the
// model as a model interface id, anything else (egress, wg, an
// interface OPF doesn't manage) as a group written back as-is.
func (p *Parser) addInterface(tok Token, ifaces *[]string) {
	switch {
	case tok.Type == TokenMacro:
		*ifaces = append(*ifaces, tok.Value)
	case p.model != nil && p.model.deviceID(tok.Value) != "":
		*ifaces = append(*ifaces, p.model.deviceID(tok.Value))
	default:
		p.groups = append(p.groups, tok.Value)
	}
}

func (p *Parser) parseProtocol() (Protocol, bool) {
	if p.check(TokenLBrace) {
		p.advance()
		items, ok := p.parseBraceList(TokenKeyword, TokenIdent, TokenNumber)
		if !ok {
			return ProtoAny, false
		}
		var protos []string
		for _, tok := range items {
			protos = append(protos, tok.Value)
		}
		// The form can only express tcp+udp as a list; anything else
		// would lose protocols.
		if len(protos) == 2 {
			if (protos[0] == "tcp" && protos[1] == "udp") ||
				(protos[0] == "udp" && protos[1] == "tcp") {
				return ProtoTCPUDP, true
			}
		}
		if len(protos) == 1 {
			return knownProtocol(protos[0])
		}
		return ProtoAny, false
	}

	if tok, ok := p.expect(TokenKeyword, TokenIdent, TokenNumber); ok {
		return knownProtocol(tok.Value)
	}
	return ProtoAny, false
}

func knownProtocol(name string) (Protocol, bool) {
	switch name {
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
	return ProtoAny, false
}

func (p *Parser) parseEndpointWithPort() (Endpoint, string, bool) {
	endpoint := Endpoint{Type: EndpointAny}
	var port string

	// The host may be omitted: "to port 22" means "to any port 22".
	if p.checkKeyword("port") {
		p.advance()
		return endpoint, p.parsePortSpec(), true
	}

	// Check for negation
	negated := false
	if p.check(TokenBang) {
		p.advance()
		negated = true
	}

	// any
	if p.checkKeyword("any") {
		p.advance()
		if negated {
			// "! any" matches nothing; the model has no way to say so.
			p.notForm = true
		}
		endpoint = Endpoint{Type: EndpointAny, Not: negated}
		// Check for port after "any"
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

	// (name[:modifiers]): an interface or group, followed as its
	// addresses change.
	if p.check(TokenLParen) {
		p.advance()
		endpoint, ok := p.parseIfaceRef(true)
		if !ok {
			p.notForm = true
		}
		endpoint.Not = negated
		if _, ok := p.expect(TokenRParen); !ok {
			p.notForm = true
		}
		if p.checkKeyword("port") {
			p.advance()
			port = p.parsePortSpec()
		}
		return endpoint, port, true
	}

	// name[:modifiers] without parentheses: resolved when the ruleset
	// loads. A bare word or $macro is only an interface if it names one;
	// otherwise pf takes it as a hostname (or the macro holds addresses).
	if p.check(TokenMacro, TokenIdent, TokenKeyword) && !p.checkKeyword("port") {
		endpoint, ok := p.parseIfaceRef(false)
		if !ok {
			return Endpoint{Type: EndpointAny}, "", false
		}
		endpoint.Not = negated
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

	// Host lists, ranges and anything else aren't modelled; the parse
	// fails, so the rule stays raw.
	return Endpoint{Type: EndpointAny}, "", false
}

func (p *Parser) parsePortSpec() string {
	// Port can be: number, range (n:m), list {n m ...}, or operator (> n, != n)
	if p.check(TokenLBrace) {
		p.advance()
		items, ok := p.parseBraceList(TokenNumber, TokenIdent, TokenKeyword)
		if !ok {
			p.notForm = true
			return ""
		}
		var ports []string
		for _, tok := range items {
			ports = append(ports, tok.Value)
		}
		return strings.Join(ports, ",")
	}

	// Operators: > >= < <= != = >< <>
	if p.check(TokenGT, TokenGTE, TokenLT, TokenLTE, TokenNE, TokenEQ) {
		op := p.advance().Value
		if tok, ok := p.expect(TokenNumber); ok {
			return op + " " + tok.Value
		}
		p.notForm = true
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

	// "port" followed by something we can't read. Dropping it would
	// turn the rule into one for every port.
	p.notForm = true
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
		// Stops at the end of the line too, so a missing ")" can't
		// swallow the following rules.
		for !p.check(TokenRParen, TokenNewline, TokenEOF) {
			switch {
			case p.checkKeyword("max"):
				p.advance()
				if n, ok := p.expectInt(); ok {
					state.MaxStates = &n
				} else {
					p.notForm = true
				}
			case p.checkKeyword("max-src-conn"):
				p.advance()
				if n, ok := p.expectInt(); ok {
					state.MaxSrcConn = &n
				} else {
					p.notForm = true
				}
			case p.checkKeyword("max-src-conn-rate"):
				// count/seconds; "3/30" tokenizes as 3, /, 30.
				p.advance()
				count, ok1 := p.expectInt()
				_, ok2 := p.expect(TokenSlash)
				secs, ok3 := p.expectInt()
				if ok1 && ok2 && ok3 {
					state.MaxSrcConnRate = &SrcConnRate{Count: count, Seconds: secs}
				} else {
					p.notForm = true
				}
			case p.checkKeyword("overload"):
				p.advance()
				if tok, ok := p.expect(TokenTable); ok {
					state.Overload = tok.Value
				} else {
					p.notForm = true
				}
				// "flush" alone (only this rule's states) isn't modelled;
				// "flush global" is.
				if _, ok := p.expectKeyword("flush"); ok {
					if _, ok := p.expectKeyword("global"); ok {
						state.FlushGlobal = true
					} else {
						p.notForm = true
					}
				}
			case p.checkKeyword("sloppy"):
				p.advance()
				state.Sloppy = true
			case p.checkKeyword("if-bound"):
				p.advance()
				state.Policy = StatePolicyIfBound
			case p.checkKeyword("floating"):
				p.advance()
				state.Policy = StatePolicyFloating
			case p.check(TokenComma):
				p.advance()
			default:
				// source-track, max-src-nodes, timeouts, no-sync, pflow
				// and so on aren't modelled.
				p.notForm = true
				p.advance()
			}
		}
		if _, ok := p.expect(TokenRParen); !ok {
			p.notForm = true
		}
	}

	return state, true
}
