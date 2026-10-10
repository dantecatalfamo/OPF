package pf

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Importing a pf.conf written by hand (Principle 4: take over a machine
// and change nothing until the admin does). Every statement keeps its
// meaning and its place:
//
//   - Rules stay in their order. A rule becomes a guided rule only where
//     the generator would write it in the same place (importRules);
//     everything else is a raw rule, its text as written.
//   - Macros, tables and options OPF can't model are kept as written in
//     custom pf's options, which come before every rule, as in the file.
//     The rest become the model's interfaces' names, aliases and the
//     firewall settings.
//   - A comment right above a rule, or after it on its line, becomes its
//     description. Other comments are lost, and said so.
//
// The appliance checks the result with pfctl (ComparePfRulesets): the
// pf.conf OPF would write has to load as the same ruleset, or the
// differences are shown before anything is taken over.

// ImportNote is something an import says about a file: what it
// understood, kept as written, left alone, or will lose.
type ImportNote struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	// Kind is one of the Note constants.
	Kind    string `json:"kind"`
	Text    string `json:"text,omitempty"` // the statement, as written
	Message string `json:"message"`
}

// Kinds of ImportNote.
const (
	// NoteModel: understood, and now part of OPF's configuration.
	NoteModel = "model"
	// NoteKept: kept as written (a raw rule, custom pf), meaning the same.
	NoteKept = "kept"
	// NoteLeft: not part of OPF's configuration; the file, interface or
	// daemon is left as it is.
	NoteLeft = "left"
	// NoteLost: the first commit loses or changes it.
	NoteLost = "lost"
)

// pfStatement is one statement of a pf.conf: a logical line, with its
// continuations joined, lists across lines put on one, and its comments
// taken off.
type pfStatement struct {
	Line    int    // where it starts
	Text    string // on one line, without comments
	Comment string // the comment right above it, and after it on its line
}

// pfComment is a comment that belongs to no statement.
type pfComment struct {
	Line int
	Text string
}

// splitPfConf splits a pf.conf into statements the way pfctl's lexer
// reads it: a backslash at the end of a line joins the next one (in a
// comment too), and a newline inside braces doesn't end a statement.
// A comment block right above a statement (no blank line between) and a
// comment after it on its line are its comment; other comments are
// returned on their own.
func splitPfConf(content string) ([]pfStatement, []pfComment) {
	var stmts []pfStatement
	var loose []pfComment
	var pending []string // comment lines waiting for a statement
	pendingLine := 0
	flush := func() {
		if len(pending) > 0 {
			loose = append(loose, pfComment{Line: pendingLine, Text: strings.Join(pending, " ")})
		}
		pending, pendingLine = nil, 0
	}

	var text strings.Builder // the statement being read
	var trailing []string    // comments inside or after it
	start, depth := 0, 0
	line := 1
	inQuote := false
	end := func() {
		t := strings.TrimSpace(collapseSpace(text.String()))
		text.Reset()
		if t == "" {
			return
		}
		c := strings.Join(append(pending, trailing...), " ")
		stmts = append(stmts, pfStatement{Line: start, Text: t, Comment: c})
		pending, pendingLine, trailing = nil, 0, nil
	}

	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case c == '\\' && i+1 < len(content) && content[i+1] == '\n':
			i++
			line++
			text.WriteByte(' ')
		case inQuote:
			text.WriteByte(c)
			if c == '"' {
				inQuote = false
			}
			if c == '\n' { // pfctl rejects it; keep the line count right
				line++
			}
		case c == '"':
			if strings.TrimSpace(text.String()) == "" {
				start = line
			}
			inQuote = true
			text.WriteByte(c)
		case c == '#':
			// To the end of the line, continuations included.
			j := i + 1
			var cb strings.Builder
			for ; j < len(content) && content[j] != '\n'; j++ {
				if content[j] == '\\' && j+1 < len(content) && content[j+1] == '\n' {
					j++
					line++
					continue
				}
				cb.WriteByte(content[j])
			}
			i = j - 1
			ct := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(cb.String()), "#"))
			if strings.TrimSpace(text.String()) == "" && depth == 0 {
				// A comment on a line of its own.
				if ct != "" && !strings.HasPrefix(ct, "$OpenBSD") {
					if len(pending) == 0 {
						pendingLine = line
					}
					pending = append(pending, ct)
				}
			} else if ct != "" {
				trailing = append(trailing, ct)
			}
		case c == '\n':
			line++
			if depth > 0 {
				text.WriteByte(' ')
				continue
			}
			if strings.TrimSpace(text.String()) == "" {
				// A blank line, or one with only a comment: a blank line
				// ends the comment block above.
				if i > 0 && lineIsBlank(content, i) {
					flush()
				}
				text.Reset()
				continue
			}
			end()
		default:
			if strings.TrimSpace(text.String()) == "" && c != ' ' && c != '\t' {
				start = line
			}
			if c == '{' {
				depth++
			} else if c == '}' && depth > 0 {
				depth--
			}
			text.WriteByte(c)
		}
	}
	end()
	flush()
	return stmts, loose
}

// lineIsBlank says whether the line ending at content[i] (a newline) is
// empty or only blanks.
func lineIsBlank(content string, i int) bool {
	j := strings.LastIndexByte(content[:i], '\n')
	return strings.TrimSpace(content[j+1:i]) == ""
}

// collapseSpace turns each run of blanks outside quotes into one space.
func collapseSpace(s string) string {
	var b strings.Builder
	inQuote, space := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote && (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		if c == '"' {
			inQuote = !inQuote
		}
		b.WriteByte(c)
	}
	return b.String()
}

var (
	macroDefRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)
	// A macro that's one device: "em0", or em0.
	deviceMacroRE = regexp.MustCompile(`^"?([a-z]+[0-9]+)"?$`)
	tableDefRE    = regexp.MustCompile(`^table\s+<([A-Za-z_][A-Za-z0-9_]*)>\s*(.*)$`)
)

// ImportPfOptions change how pf.conf is imported.
type ImportPfOptions struct {
	// ExplicitDefault writes pf's default for a packet no rule matches
	// (pass it, keeping no state) as the first rule: needed when no rule
	// of the file matches every packet, since OPF's own default rules
	// come before the imported ones (ComparePfRulesets).
	ExplicitDefault bool
}

// importPfConf imports a pf.conf into m, whose interfaces are already
// imported: it may rename them after the file's macros for them. It
// returns what it found.
func importPfConf(m *Model, content string, opts ImportPfOptions) []ImportNote {
	const file = "/etc/pf.conf"
	var notes []ImportNote
	note := func(s pfStatement, kind, format string, args ...any) {
		notes = append(notes, ImportNote{File: file, Line: s.Line, Kind: kind, Text: s.Text, Message: fmt.Sprintf(format, args...)})
	}
	stmts, loose := splitPfConf(content)
	for _, c := range loose {
		notes = append(notes, ImportNote{File: file, Line: c.Line, Kind: NoteLost, Text: "# " + c.Text, Message: "a comment that isn't right above a rule isn't kept"})
	}

	fw := &m.Firewall
	o := &fw.Options
	var custom []string // macros, tables and options kept as written, in order
	var rules []pfStatement

	// Macros: one naming a device the model has, defined once, becomes
	// that interface's name in the model, which the generator defines
	// the same way.
	defs := map[string]int{}
	for _, s := range stmts {
		if sub := macroDefRE.FindStringSubmatch(s.Text); sub != nil {
			defs[sub[1]]++
		}
	}
	ifaceMacros := map[string]bool{}
	for _, s := range stmts {
		sub := macroDefRE.FindStringSubmatch(s.Text)
		if sub == nil || defs[sub[1]] != 1 || !ifaceIDRE.MatchString(sub[1]) {
			continue
		}
		dev := deviceMacroRE.FindStringSubmatch(sub[2])
		if dev == nil {
			continue
		}
		for i := range m.Interfaces {
			if m.Interfaces[i].Device == dev[1] && m.Interfaces[i].Enabled && !ifaceMacros[m.Interfaces[i].ID] {
				renameIface(m, m.Interfaces[i].ID, sub[1])
				ifaceMacros[sub[1]] = true
				break
			}
		}
	}
	// Every other interface's name must not be one of the file's macros,
	// which the generator's would replace.
	for i := range m.Interfaces {
		id := m.Interfaces[i].ID
		if ifaceMacros[id] || defs[id] == 0 {
			continue
		}
		renameIface(m, id, freeIfaceID(m, id, defs))
	}

	for _, s := range stmts {
		switch first := firstWord(s.Text); {
		case macroDefRE.MatchString(s.Text) && first != "set" && first != "table":
			name := macroDefRE.FindStringSubmatch(s.Text)[1]
			if ifaceMacros[name] {
				note(s, NoteModel, "the name of interface %s", ifaceByID(m, name).Device)
				continue
			}
			custom = append(custom, s.Text)
			note(s, NoteKept, "a macro, kept as written in custom pf")
		case first == "set":
			if importSetOption(m, s.Text) {
				note(s, NoteModel, "a firewall setting")
				continue
			}
			custom = append(custom, s.Text)
			note(s, NoteKept, "a setting OPF doesn't have, kept as written in custom pf")
		case first == "table":
			if a, ok := importTable(m, s.Text); ok {
				a.Description = importDescription(s.Comment)
				fw.Aliases = append(fw.Aliases, a)
				note(s, NoteModel, "the alias %s", a.Name)
				continue
			}
			custom = append(custom, s.Text)
			note(s, NoteKept, "a table, kept as written in custom pf")
		default:
			rules = append(rules, s)
		}
	}
	fw.Custom.Options = strings.Join(custom, "\n")
	// The generator always leaves lo unfiltered, before the rest.
	if !slices.Contains(o.SkipOn, "lo") {
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Text: "set skip on lo", Message: "OPF always leaves the loopback interface unfiltered, which this file doesn't"})
	}
	o.SkipOn = slices.DeleteFunc(o.SkipOn, func(s string) bool { return s == "lo" })
	notes = append(notes, importRules(m, rules, opts)...)
	return notes
}

func firstWord(s string) string {
	w, _, _ := strings.Cut(s, " ")
	return w
}

// renameIface gives an interface a new id, everywhere the model refers
// to it so far: routing and DHCP (the rest is imported later).
func renameIface(m *Model, from, to string) {
	if from == to {
		return
	}
	for i := range m.Interfaces {
		if m.Interfaces[i].ID == from {
			m.Interfaces[i].ID = to
		}
		if v := m.Interfaces[i].VLAN; v != nil && v.Parent == from {
			v.Parent = to
		}
	}
	for i := range m.Routing.Gateways {
		if m.Routing.Gateways[i].Iface == from {
			m.Routing.Gateways[i].Iface = to
		}
	}
	for i := range m.DHCP {
		if m.DHCP[i].Iface == from {
			m.DHCP[i].Iface = to
		}
	}
}

// freeIfaceID is id, or id with a number after it, that's neither an
// interface's nor one of the file's macros.
func freeIfaceID(m *Model, id string, macros map[string]int) string {
	for n := 2; ; n++ {
		c := fmt.Sprintf("%s%d", id, n)
		if macros[c] == 0 && ifaceByID(m, c) == nil {
			return c
		}
	}
}

// importDescription is a comment as a description: one line, at most
// 200 bytes, without the backslashes and dollar signs descriptions
// can't have.
func importDescription(c string) string {
	c = strings.Map(func(r rune) rune {
		switch {
		case r == '\\' || r == '$':
			return -1
		case r < ' ' || r == 0x7f:
			return ' '
		}
		return r
	}, c)
	c = strings.TrimSpace(collapseSpace(c))
	if len(c) > 200 {
		cut := 197
		for cut > 0 && !utf8RuneStart(c[cut]) {
			cut--
		}
		c = c[:cut] + "..."
	}
	return c
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// importTable makes an alias of a table OPF can write the same way: a
// const one with addresses and networks only (written back const), or
// a persist one with nothing in it (an address table OPF and pf fill).
func importTable(m *Model, text string) (Alias, bool) {
	sub := tableDefRE.FindStringSubmatch(text)
	if sub == nil || !tableRE.MatchString(sub[1]) {
		return Alias{}, false
	}
	name, rest := sub[1], strings.Fields(sub[2])
	for _, a := range m.Firewall.Aliases {
		if a.Name == name {
			return Alias{}, false // defined twice: pfctl decides
		}
	}
	id := fmt.Sprintf("imp-%s", strings.ToLower(name))
	if len(id) > 64 {
		id = id[:64]
	}
	switch {
	case slices.Equal(rest, []string{"persist"}):
		return Alias{ID: id, Name: name, Type: AliasTable, Entries: []string{}}, true
	case len(rest) >= 3 && rest[0] == "const" && rest[1] == "{" && rest[len(rest)-1] == "}":
		var entries []string
		hosts := true
		for _, e := range rest[2 : len(rest)-1] {
			e = strings.TrimSuffix(e, ",")
			if e == "" {
				continue
			}
			switch {
			case isIPAddr(e):
			case isCIDR(e):
				hosts = false
			default:
				return Alias{}, false // a name, a macro, a negation
			}
			entries = append(entries, e)
		}
		if len(entries) == 0 {
			return Alias{}, false
		}
		t := AliasHosts
		if !hosts {
			t = AliasNetworks
		}
		return Alias{ID: id, Name: name, Type: t, Entries: entries}, true
	}
	return Alias{}, false
}

func isIPAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func isCIDR(s string) bool {
	a, p, ok := strings.Cut(s, "/")
	if !ok || !isIPAddr(a) {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 0 && n <= 128
}

// importSetOption puts a set option into the firewall settings when the
// model has it exactly; false leaves it to be kept as written.
func importSetOption(m *Model, text string) bool {
	o := &m.Firewall.Options
	f := strings.Fields(strings.NewReplacer("{", " { ", "}", " } ", ",", " ").Replace(text))
	if len(f) < 3 {
		return false
	}
	one := func(allowed ...string) (string, bool) {
		if len(f) != 3 || !slices.Contains(allowed, f[2]) {
			return "", false
		}
		return f[2], true
	}
	// A value or a { list } of name value pairs.
	pairs := func() ([][2]string, bool) {
		items := f[2:]
		if items[0] == "{" {
			if items[len(items)-1] != "}" {
				return nil, false
			}
			items = items[1 : len(items)-1]
		}
		if len(items) == 0 || len(items)%2 != 0 {
			return nil, false
		}
		var out [][2]string
		for i := 0; i < len(items); i += 2 {
			out = append(out, [2]string{items[i], items[i+1]})
		}
		return out, true
	}
	switch f[1] {
	case "block-policy":
		v, ok := one("drop", "return")
		o.BlockPolicy = BlockPolicy(v)
		return ok
	case "state-policy":
		v, ok := one("if-bound", "floating")
		o.StatePolicy = StatePolicyOption(v)
		return ok
	case "optimization":
		v, ok := one("normal", "high-latency", "satellite", "aggressive", "conservative")
		if v == "satellite" {
			v = "high-latency" // the same, by another name
		}
		o.Optimization = Optimization(v)
		return ok
	case "ruleset-optimization":
		v, ok := one("none", "basic", "profile")
		o.RulesetOptimization = v
		return ok
	case "syncookies":
		if v, ok := one("never", "always"); ok {
			o.Syncookies = Syncookies(v)
			return true
		}
		return false // adaptive's percentages: kept as written
	case "debug":
		v, ok := one("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
		o.Debug = v
		return ok
	case "loginterface":
		if len(f) != 3 {
			return false
		}
		if f[2] == "none" {
			o.LogInterface = "none"
			return true
		}
		if id := m.deviceID(f[2]); id != "" {
			o.LogInterface = id
			return true
		}
		if id, ok := strings.CutPrefix(f[2], "$"); ok && ifaceByID(m, id) != nil {
			o.LogInterface = id
			return true
		}
		return false
	case "limit":
		ps, ok := pairs()
		if !ok {
			return false
		}
		l := o.Limits
		states := o.MaxStates
		for _, p := range ps {
			n, err := strconv.Atoi(p[1])
			if err != nil || n < 0 {
				return false
			}
			// pfctl matches the pool's name ignoring case.
			i := slices.Index(LimitNames, strings.ToLower(p[0]))
			switch {
			case i == 0:
				states = n
			case i > 0:
				*l.pointers()[i-1] = &n
			default:
				return false
			}
		}
		o.Limits, o.MaxStates = l, states
		return true
	case "timeout":
		ps, ok := pairs()
		if !ok {
			return false
		}
		t := map[string]int{}
		for k, v := range o.Timeouts {
			t[k] = v
		}
		for _, p := range ps {
			n, err := strconv.Atoi(strings.TrimSuffix(p[1], "s"))
			if err != nil || n < 0 || !slices.Contains(TimeoutNames, p[0]) {
				return false
			}
			t[p[0]] = n
		}
		o.Timeouts = t
		return true
	case "skip":
		if f[2] != "on" || len(f) < 4 {
			return false
		}
		items := f[3:]
		if items[0] == "{" {
			if items[len(items)-1] != "}" || len(items) < 3 {
				return false
			}
			items = items[1 : len(items)-1]
		}
		var add []string
		for _, it := range items {
			name := it
			if id, ok := strings.CutPrefix(it, "$"); ok {
				if ifaceByID(m, id) == nil {
					return false
				}
				name = id
			} else if id := m.deviceID(it); id != "" {
				name = id
			} else if !(groupRE.MatchString(it) || deviceRE.MatchString(it)) {
				return false
			}
			add = append(add, name)
		}
		for _, a := range add {
			if !slices.Contains(o.SkipOn, a) {
				o.SkipOn = append(o.SkipOn, a)
			}
		}
		return true
	}
	return false
}

// importRules makes the model's rules of the file's rules, in order.
//
// The generator writes the rules that aren't on one interface first
// ("floating", raw rules among them), then each interface's in the
// model's order of interfaces. So only a run at the end of the file,
// grouped by interface, can be guided rules on one interface each:
// before that run, a rule on one interface is kept as written, which
// puts it with the floating rules, in place.
func importRules(m *Model, stmts []pfStatement, opts ImportPfOptions) []ImportNote {
	const file = "/etc/pf.conf"
	var notes []ImportNote
	type parsed struct {
		s    pfStatement
		rule Rule
	}
	var all []parsed
	if opts.ExplicitDefault {
		all = append(all, parsed{
			s:    pfStatement{Text: ExplicitDefaultRule},
			rule: Rule{Kind: "raw", Enabled: true, Interfaces: []string{}, Text: ExplicitDefaultRule, Description: "What pf does with a packet no rule matches: OPF's own rules come first, so it's written out"},
		})
		notes = append(notes, ImportNote{File: file, Kind: NoteKept, Text: ExplicitDefaultRule, Message: "pf's default for a packet no rule matches, written out as the first rule: none of the file's rules matches every packet, and OPF's own default rules come before them"})
	}
	for _, s := range stmts {
		r := Rule{Kind: "raw", Enabled: true, Interfaces: []string{}, Text: s.Text}
		switch firstWord(s.Text) {
		case "pass", "block", "match":
			if pr, err := ParseRule(s.Text, m); err == nil && pr != nil {
				r = *pr
				if r.Kind == "raw" {
					r.Text = s.Text
				}
			}
		}
		if d := importDescription(s.Comment); d != "" {
			r.Description = d
		}
		all = append(all, parsed{s, r})
	}

	// A guided rule the model can't have as it is (an alias kept as
	// written, say) is kept as written.
	for {
		trial := *m
		trial.Firewall.Rules = nil
		for _, p := range all {
			trial.Firewall.Rules = append(trial.Firewall.Rules, p.rule)
		}
		for i := range trial.Firewall.Rules {
			trial.Firewall.Rules[i].ID = fmt.Sprintf("imp%d", i+1)
		}
		bad := map[int]bool{}
		for _, e := range Validate(&trial) {
			var i int
			if _, err := fmt.Sscanf(e.Path, "firewall.rules[%d]", &i); err == nil && all[i].rule.Kind == "form" {
				bad[i] = true
			}
		}
		if len(bad) == 0 {
			break
		}
		for i := range bad {
			all[i].rule = Rule{Kind: "raw", Enabled: true, Interfaces: []string{}, Text: all[i].s.Text, Description: all[i].rule.Description}
		}
	}

	// The run at the end: from the last rule back, while each is a
	// guided rule on one model interface and the interfaces' groups
	// don't interleave.
	single := func(r *Rule) bool { return r.Kind == "form" && !isFloating(r) && ifaceByID(m, r.Interfaces[0]) != nil }
	runStart := len(all)
	var order []string // the run's interfaces, last first
	for i := len(all) - 1; i >= 0; i-- {
		r := &all[i].rule
		if !single(r) {
			break
		}
		id := r.Interfaces[0]
		if len(order) == 0 || order[len(order)-1] != id {
			if slices.Contains(order, id) {
				break // the interface's rules would be put together
			}
			order = append(order, id)
		}
		runStart = i
	}
	// The model's interfaces in the run's order, the others first as
	// they were.
	slices.Reverse(order)
	var ifaces []Iface
	for _, i := range m.Interfaces {
		if !slices.Contains(order, i.ID) {
			ifaces = append(ifaces, i)
		}
	}
	for _, id := range order {
		ifaces = append(ifaces, *ifaceByID(m, id))
	}
	m.Interfaces = ifaces

	n := 0
	for i := range all {
		p := &all[i]
		if p.rule.Kind == "form" && !isFloating(&p.rule) && i < runStart {
			// On one interface, but the generator would move it.
			p.rule = Rule{Kind: "raw", Enabled: true, Interfaces: []string{}, Text: p.s.Text, Description: p.rule.Description}
		}
		n++
		p.rule.ID = fmt.Sprintf("imp%d", n)
		if p.s.Line == 0 {
			// The explicit default, noted above.
		} else if p.rule.Kind == "form" {
			notes = append(notes, ImportNote{File: file, Line: p.s.Line, Kind: NoteModel, Text: p.s.Text, Message: "a rule"})
		} else {
			why := "kept as written"
			switch firstWord(p.s.Text) {
			case "pass", "block", "match":
				if strings.Contains(p.s.Text, " label ") {
					why = "a rule with a label of its own, kept as written"
				} else {
					why = "a rule, kept as written"
				}
			case "anchor", "load":
				why = "an anchor, kept as written"
			case "include":
				why = "an included file, kept as written; OPF doesn't take it over"
			}
			notes = append(notes, ImportNote{File: file, Line: p.s.Line, Kind: NoteKept, Text: p.s.Text, Message: why})
		}
		m.Firewall.Rules = append(m.Firewall.Rules, p.rule)
	}
	return notes
}
