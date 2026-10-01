package appliance

import (
	"context"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Tools for the resolver, over unbound's control socket: where it
// would look a name up, what it has cached for it, its local data, and
// forgetting cached answers. Looking reads; forgetting changes unbound's
// cache, so it runs as an action (logged instead under -dry). A name is
// a DNS name, checked, so it can't be taken for an option.

// DNSToolRequest is a tool and, for those that take one, a name.
type DNSToolRequest struct {
	// Tool: "lookup" (the servers it would ask), "cache" (what it has
	// cached for the name and under it), "local" (its local zones and
	// data), "flush" (forget the name), "flush_zone" (forget everything
	// under it), "flush_bogus" (forget answers that failed DNSSEC) or
	// "flush_negative" (forget "no such name" and empty answers).
	Tool string `json:"tool"`
	Name string `json:"name,omitempty"`
}

// DNSToolResult is what the tool printed, a line each.
type DNSToolResult struct {
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated,omitempty"`
}

const maxToolLines = 1000

var dnsTools = map[string]struct {
	name   bool // takes a name
	change bool // changes unbound's state
}{
	"lookup": {name: true}, "cache": {name: true}, "local": {},
	"flush": {name: true, change: true}, "flush_zone": {name: true, change: true},
	"flush_bogus": {change: true}, "flush_negative": {change: true},
}

// isDNSName is a name unbound-control takes: labels of letters, digits,
// hyphens and underscores, a final dot optional.
func isDNSName(s string) bool {
	return s != "" && s != "." && !strings.HasPrefix(s, "*") && pf.IsBlockName(s)
}

// DNSTool runs a resolver tool.
func (m *Manager) DNSTool(req DNSToolRequest) (*DNSToolResult, error) {
	t, ok := dnsTools[req.Tool]
	if !ok {
		return nil, errorf(CodeInvalid, "no resolver tool %q", printable(req.Tool, 40))
	}
	name := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(req.Name)), ".")
	if t.name && !isDNSName(name) {
		return nil, &Error{Code: CodeInvalid, Message: "enter a name like example.com", Details: []Detail{{Path: "name", Message: "enter a name like example.com"}}}
	}
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	if model == nil || !model.DNS.Enabled {
		return nil, errorf(CodeInvalid, "the resolver isn't running")
	}
	ctl := func(args ...string) (string, error) {
		argv := append([]string{"unbound-control", "-c", unboundConf}, args...)
		if t.change {
			ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
			defer cancel()
			out, err := m.actions().Run(ctx, argv...)
			return string(out), err
		}
		return m.read(argv...)
	}
	var out string
	switch req.Tool {
	case "lookup":
		out, err = ctl("lookup", name+".")
	case "cache":
		// The whole cache, then only the lines about the name and what's
		// under it.
		var all string
		all, err = ctl("dump_cache")
		out = cacheLines(all, name)
	case "local":
		var zones, data string
		zones, err = ctl("list_local_zones")
		if err == nil {
			data, err = ctl("list_local_data")
		}
		out = zones + data
	case "flush":
		out, err = ctl("flush", name+".")
	case "flush_zone":
		out, err = ctl("flush_zone", name+".")
	case "flush_bogus":
		out, err = ctl("flush_bogus")
	case "flush_negative":
		out, err = ctl("flush_negative")
	}
	res := &DNSToolResult{Lines: []string{}}
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if l == "" {
			continue
		}
		if len(res.Lines) == maxToolLines {
			res.Truncated = true
			break
		}
		res.Lines = append(res.Lines, logText(l))
	}
	if err != nil {
		return nil, errorf(CodeInternal, "unbound-control didn't answer: %s", firstLine(out))
	}
	return res, nil
}

// cacheLines are the lines of dump_cache about name or what's under it:
// records whose owner is one of them, and messages asked for one.
func cacheLines(dump, name string) string {
	var b strings.Builder
	fqdn := name + "."
	for _, l := range strings.Split(dump, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], ";") || strings.HasPrefix(f[0], "START_") || strings.HasPrefix(f[0], "END_") || f[0] == "EOF" {
			continue
		}
		owner := strings.ToLower(f[0])
		if f[0] == "msg" && len(f) > 1 {
			owner = strings.ToLower(f[1])
		}
		if owner == fqdn || strings.HasSuffix(owner, "."+fqdn) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}
