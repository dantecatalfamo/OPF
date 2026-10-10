package pf

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Whether two pf.conf files load as the same ruleset, judged from what
// pfctl -nvf prints for each: the ruleset pfctl parsed, with macros
// expanded, lists made into rules, and every option and table it set.
// An import is checked this way: the machine's own pf.conf against the
// one OPF would write in its place.
//
// What OPF's file adds that doesn't change what pf does is set aside:
//
//   - macro definitions (expanded in the rules either way);
//   - OPF's labels on its rules (labels only name a rule's counters);
//   - options set to what pf has when they aren't set (pfDefaults);
//   - the order tables and options come in (they hold for the whole
//     ruleset, wherever they're set);
//   - OPF's default rules (block all, pass out), which come before the
//     imported ones: pf takes the last rule that matches a packet, so
//     they decide only for a packet no imported rule matches, and when
//     one of those matches every packet (catchAllRE), none is left.
//     Without one, the import writes pf's own default out instead
//     (ImportPfOptions.ExplicitDefault).

// PfComparison is the result of comparing two pfctl -nv outputs.
type PfComparison struct {
	Same bool `json:"same"`
	// NoCatchAll: OPF's default rules would decide for packets the
	// machine's rules match none of; importing again with
	// ExplicitDefault is the cure.
	NoCatchAll bool `json:"noCatchAll,omitempty"`
	// Differences say what differs, one per line.
	Differences []string `json:"differences"`
	// Machine and OPF are the normalized rulesets compared.
	Machine []string `json:"machine"`
	OPF     []string `json:"opf"`
}

// pfDefaults are the options OPF's pf.conf always sets, with pf's value
// when pf.conf doesn't.
var pfDefaults = map[string]string{
	"block-policy": "drop",
	"state-policy": "floating",
	"optimization": "normal",
	"limit states": fmt.Sprint(PfDefaultStates),
	"syncookies":   "never",
	"loginterface": "none",
}

var (
	pfMacroLineRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]* = `)
	opfLabelRE    = regexp.MustCompile(` label "` + regexp.QuoteMeta(labelPrefix) + `[^"]*"`)
	builtinRE     = regexp.MustCompile(` label "` + regexp.QuoteMeta(Label(LabelBuiltin, "")) + `[^"]*"`)
	// A rule that matches every packet, as pfctl prints it: no
	// direction, interface, family, protocol or address. pfctl writes
	// return-rst's ttl and return-icmp's codes without a space before
	// the parenthesis (print_rule).
	catchAllRE = regexp.MustCompile(`^(?:block(?: (?:drop|return|return-rst(?: ?\(ttl \d+\))?|return-icmp(?:6)?(?: ?\([^)]*\))?))?|pass)(?: log(?: \([^)]*\))?)?(?: quick)? all(?: flags \S+)?(?: (?:keep|modulate|synproxy) state(?: \([^)]*\))?| no state)?(?: label "[^"]*")?$`)
	// Lines pfctl -v prints that aren't the ruleset.
	pfNoiseRE = regexp.MustCompile(`^Loaded \d+ passive OS fingerprints$`)
)

// pfNormalized is a pfctl -nv output taken apart.
type pfNormalized struct {
	options map[string]string
	skip    []string
	tables  []string
	rules   []string
}

func normalizePfctl(out string) pfNormalized {
	n := pfNormalized{options: map[string]string{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || pfNoiseRE.MatchString(line) || pfMacroLineRE.MatchString(line):
		case strings.HasPrefix(line, "set skip on "):
			for _, f := range strings.Fields(strings.Trim(strings.TrimPrefix(line, "set skip on "), "{} ")) {
				if !slices.Contains(n.skip, f) {
					n.skip = append(n.skip, f)
				}
			}
		case strings.HasPrefix(line, "set "):
			f := strings.Fields(strings.TrimPrefix(line, "set "))
			if len(f) < 2 {
				n.rules = append(n.rules, line)
				continue
			}
			n.options[strings.Join(f[:len(f)-1], " ")] = f[len(f)-1]
		case strings.HasPrefix(line, "table "):
			n.tables = append(n.tables, line)
		default:
			n.rules = append(n.rules, line)
		}
	}
	slices.Sort(n.skip)
	slices.Sort(n.tables)
	return n
}

// ExplicitDefaultRule is pf's default for a packet no rule matches, as
// a rule: pass it, keeping no state. pfctl prints it as written.
const ExplicitDefaultRule = "pass all no state"

// ComparePfRulesets compares the pfctl -nv output of the machine's
// pf.conf with that of the one OPF would write. explicitDefault says the
// import wrote pf's default out as OPF's first rule
// (ImportPfOptions.ExplicitDefault): the machine's rules are compared
// with it in front, which is what pf does with them anyway.
func ComparePfRulesets(machine, opf string, explicitDefault bool) *PfComparison {
	a, b := normalizePfctl(machine), normalizePfctl(opf)
	if explicitDefault {
		a.rules = append([]string{ExplicitDefaultRule}, a.rules...)
	}
	res := &PfComparison{Differences: []string{}}
	diff := func(format string, args ...any) {
		res.Differences = append(res.Differences, fmt.Sprintf(format, args...))
	}

	// Options, with pf's defaults where they aren't set.
	keys := map[string]bool{}
	for k := range a.options {
		keys[k] = true
	}
	for k := range b.options {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		va, oka := a.options[k]
		vb, okb := b.options[k]
		if !oka {
			va, oka = pfDefaults[k]
		}
		if !okb {
			vb, okb = pfDefaults[k]
		}
		switch {
		case !oka:
			diff("OPF's sets %q, which the machine's leaves as pf has it", "set "+k+" "+vb)
		case !okb:
			diff("the machine's sets %q, which OPF's leaves as pf has it", "set "+k+" "+va)
		case va != vb:
			diff("set %s: %s on the machine, %s in OPF's", k, va, vb)
		}
	}
	if !slices.Equal(a.skip, b.skip) {
		diff("unfiltered interfaces (set skip on): %s on the machine, %s in OPF's", listOrNone(a.skip), listOrNone(b.skip))
	}
	for _, t := range a.tables {
		if !slices.Contains(b.tables, t) {
			diff("only the machine's has %s", t)
		}
	}
	for _, t := range b.tables {
		if !slices.Contains(a.tables, t) {
			diff("only OPF's has %s", t)
		}
	}

	// Rules: OPF's defaults set aside when one of the machine's rules
	// matches every packet, then OPF's labels.
	catchAll := slices.ContainsFunc(a.rules, catchAllRE.MatchString)
	var opfRules []string
	for _, r := range b.rules {
		if builtinRE.MatchString(r) {
			if catchAll {
				continue
			}
			res.NoCatchAll = true
		}
		opfRules = append(opfRules, strings.TrimSpace(opfLabelRE.ReplaceAllString(r, "")))
	}
	res.Machine, res.OPF = a.rules, opfRules
	if res.NoCatchAll {
		diff("none of the machine's rules matches every packet, so OPF's default rules would decide for those no rule matches")
	}
	for _, d := range lineDiff(a.rules, opfRules) {
		diff("%s", d)
	}
	res.Same = len(res.Differences) == 0
	return res
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}

// lineDiff describes how b's lines differ from a's, from their longest
// common subsequence: each line only one has, and where.
func lineDiff(a, b []string) []string {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, fmt.Sprintf("rule %d only on the machine: %s", i+1, a[i]))
			i++
		default:
			out = append(out, fmt.Sprintf("rule %d only in OPF's: %s", j+1, b[j]))
			j++
		}
	}
	return out
}
