package conformance

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// SourceFacts are names OPF takes from the release's source. The suite
// reads them from the source on OpenBSD (TestSource) and saves them as
// source.json; Problems compares them with OPF's own lists, there and on
// any machine.
type SourceFacts struct {
	Release string `json:"release"`
	// pfctl
	PfctlParseY   string     `json:"pfctlParseY"` // parse.y's revision
	PfKeywords    []string   `json:"pfKeywords"`
	PfLimits      []string   `json:"pfLimits"`
	PfTimeouts    []string   `json:"pfTimeouts"`
	ICMPTypes     [][]string `json:"icmpTypes"` // name, type constant
	ICMP6Types    [][]string `json:"icmp6Types"`
	ICMPCodes     [][]string `json:"icmpCodes"` // name, its type's constant
	ICMP6Codes    [][]string `json:"icmp6Codes"`
	PfCounters    []string   `json:"pfCounters"`    // PFRES_NAMES
	LimitCounters []string   `json:"limitCounters"` // LCNT_NAMES
	// ntpd
	NtpdKeywords []string `json:"ntpdKeywords"`
	// /etc/netstart: the kinds its first pass skips, those started in
	// the second pass (after the physical ports) and the third (once
	// routes are up).
	NetstartSkipped []string `json:"netstartSkipped"`
	// sys/net/if_trunk.h: trunk(4)'s protocols (TRUNK_PROTOS), by name.
	TrunkProtos     []string `json:"trunkProtos,omitempty"`
	NetstartLower   []string `json:"netstartLower"`
	NetstartRouting []string `json:"netstartRouting"`
}

var (
	cvsRevRE  = regexp.MustCompile(`\$OpenBSD: parse\.y,v ([0-9.]+) `)
	cEntryRE  = regexp.MustCompile(`\{\s*"([^"]*)"\s*,\s*([A-Za-z0-9_]+)`)
	cStringRE = regexp.MustCompile(`"([^"]*)"`)
	ifmRE     = regexp.MustCompile(`(?m)^ifmstart ((?:"[^"]*" ?)+)$`)
	// A table ends at the first "};" on a line of its own.
	tableEndRE = regexp.MustCompile(`\n\s*\};`)
)

// cTable is the names in a C array of { "name", CONST, … } entries,
// declared as decl ("pf_timeouts[]"), with each entry's first constant.
func cTable(src, decl string) ([][]string, error) {
	start := strings.Index(src, decl+" = {")
	if start < 0 {
		return nil, fmt.Errorf("no %s", decl)
	}
	end := tableEndRE.FindStringIndex(src[start:])
	if end == nil {
		return nil, fmt.Errorf("%s has no end", decl)
	}
	var out [][]string
	for _, m := range cEntryRE.FindAllStringSubmatch(src[start:start+end[0]], -1) {
		out = append(out, []string{m[1], m[2]})
	}
	return out, nil
}

func firsts(entries [][]string) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e[0])
	}
	return out
}

// cMacroStrings is the strings in a #define NAME { "a", "b", … } macro.
func cMacroStrings(src, name string) ([]string, error) {
	loc := regexp.MustCompile(`#define[ \t]+` + regexp.QuoteMeta(name) + `[ \t]+\{`).FindStringIndex(src)
	if loc == nil {
		return nil, fmt.Errorf("no %s", name)
	}
	// The macro goes on while its lines end in a backslash; its entries
	// may be braced pairs, { "name", CONST }.
	body := src[loc[0]:]
	for i := 0; ; {
		nl := strings.IndexByte(body[i:], '\n')
		if nl < 0 {
			break
		}
		if !strings.HasSuffix(strings.TrimRight(body[i:i+nl], " \t"), "\\") {
			body = body[:i+nl]
			break
		}
		i += nl + 1
	}
	var out []string
	for _, m := range cStringRE.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out, nil
}

// yaccKeywords is a parse.y's keywords table, sorted.
func yaccKeywords(src string) ([]string, error) {
	start := strings.Index(src, "static const struct keywords keywords[] = {")
	if start < 0 {
		return nil, fmt.Errorf("no keywords table")
	}
	t, err := cTable(src[start:], "keywords[]")
	if err != nil {
		return nil, err
	}
	out := firsts(t)
	slices.Sort(out)
	return out, nil
}

// netstartPasses are the kinds of interface netstart's first pass
// skips (ifmstart "" "aggr trunk …"), and those it starts in its second
// and third passes (ifmstart "aggr trunk …" and "tun tap …").
func netstartPasses(netstart string) (skipped, lower, routing []string, err error) {
	var passes [][]string
	for _, m := range ifmRE.FindAllStringSubmatch(netstart, -1) {
		args := cStringRE.FindAllStringSubmatch(m[1], -1)
		switch {
		case len(args) == 2 && args[0][1] == "" && skipped == nil:
			skipped = strings.Fields(args[1][1])
		case len(args) == 1:
			passes = append(passes, strings.Fields(args[0][1]))
		default:
			return nil, nil, nil, fmt.Errorf("netstart has an ifmstart OPF doesn't know: %s", m[0])
		}
	}
	if skipped == nil || len(passes) != 2 {
		return nil, nil, nil, fmt.Errorf("netstart has %d one-list ifmstart passes and a first pass %v, OPF knows two and one", len(passes), skipped != nil)
	}
	return skipped, passes[0], passes[1], nil
}

// Problems compares the source's names with OPF's.
func (f SourceFacts) Problems() []string {
	var p []string
	same := func(what string, release, opf []string) {
		r, o := slices.Sorted(slices.Values(release)), slices.Sorted(slices.Values(opf))
		for _, n := range r {
			if !slices.Contains(o, n) {
				p = append(p, fmt.Sprintf("%s: %s has %q, OPF doesn't", what, f.Release, n))
			}
		}
		for _, n := range o {
			if !slices.Contains(r, n) {
				p = append(p, fmt.Sprintf("%s: OPF has %q, %s doesn't", what, n, f.Release))
			}
		}
	}
	same("pfctl's keywords (regenerate internal/pf/keywords_gen.go with genkeywords)", f.PfKeywords, pf.Keywords())
	same("set limit's pools (pf.LimitNames)", f.PfLimits, pf.LimitNames)
	same("set timeout's names (pf.TimeoutNames)", f.PfTimeouts, pf.TimeoutNames)
	same("ntpd.conf's keywords (pf.NTPKeywords)", f.NtpdKeywords, pf.NTPKeywords())
	if f.TrunkProtos != nil { // not in captures before 2026-10-13
		// lacp is aggr's in OPF, and default another name for roundrobin.
		opf := []string{"lacp", "default"}
		for _, p := range pf.TrunkProtos {
			opf = append(opf, string(p))
		}
		same("trunk(4)'s protocols (pf.TrunkProtos)", f.TrunkProtos, opf)
	}

	// netstart's passes against the order OPF applies interfaces in
	// (config.netstartOrder): the first pass starts all but the kinds it
	// skips, by name, and the others follow kind by kind.
	inOrder := func(what string, release, opf []string) {
		if !slices.Equal(release, opf) {
			p = append(p, fmt.Sprintf("netstart's %s: %s has %v, OPF %v", what, f.Release, release, opf))
		}
	}
	if f.NetstartSkipped != nil { // not in captures before 2026-10-13
		inOrder("first pass skips", f.NetstartSkipped, slices.Concat(config.NetstartLower, config.NetstartRouting))
	}
	inOrder("second pass", f.NetstartLower, config.NetstartLower)
	inOrder("third pass", f.NetstartRouting, config.NetstartRouting)
	return p
}
