package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// releases are the releases the suite has captured, by directory
// (testdata/openbsd-<release>/captures).
func releases(t *testing.T) []string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join("testdata", "openbsd-*", "captures"))
	if len(dirs) == 0 {
		t.Fatal("no testdata/openbsd-*/captures: run scripts/conformance/run.sh")
	}
	return dirs
}

func uiFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "ui", "src", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// section is the part of a TypeScript file from "export const name" to
// the next export.
func section(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "export const "+name)
	if i < 0 {
		t.Fatalf("no export const %s", name)
	}
	rest := src[i+1:]
	if j := strings.Index(rest, "\nexport "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func all(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// subset reports names in ui that the release doesn't have.
func subset(what string, ui, release []string) []string {
	var p []string
	for _, n := range ui {
		if !slices.Contains(release, n) {
			p = append(p, fmt.Sprintf("%s: the UI has %q, which the release doesn't", what, n))
		}
	}
	return p
}

func sameSet(what string, ui, release []string) []string {
	p := subset(what, ui, release)
	for _, n := range release {
		if !slices.Contains(ui, n) {
			p = append(p, fmt.Sprintf("%s: the release has %q, which the UI doesn't", what, n))
		}
	}
	return p
}

// TestSourceFacts compares the names each release's source has
// (source.json, saved by TestSource on OpenBSD) with OPF's lists, in Go
// and in the UI, which builds pf rules and shows pf's counters by name.
func TestSourceFacts(t *testing.T) {
	inRepo(t)
	icmp := uiFile(t, "lib/icmp.ts")
	typeRE := regexp.MustCompile(`(?m)^    name: '([^']+)'`)
	codeRE := regexp.MustCompile(`\{ name: '([^']+)'`)
	valueRE := regexp.MustCompile(`value: '([^']+)'`)
	nameRE := regexp.MustCompile(`name: '([^']+)'`)
	quotedRE := regexp.MustCompile(`'([a-z0-9.]+)'`)
	stats := uiFile(t, "pages/FirewallStats.tsx")
	statList := func(decl string) []string {
		i := strings.Index(stats, decl)
		if i < 0 {
			t.Fatalf("FirewallStats.tsx has no %s", decl)
		}
		j := strings.Index(stats[i:], "\n];")
		return all(nameRE, stats[i:i+j])
	}

	for _, dir := range releases(t) {
		data, err := os.ReadFile(filepath.Join(dir, "source.json"))
		if err != nil {
			t.Fatal(err)
		}
		var f SourceFacts
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		t.Run(f.Release, func(t *testing.T) {
			p := f.Problems()
			// ICMP types and codes, which the rule form writes into pf
			// rules: each code under its own type.
			for _, fam := range []struct {
				section, ret string
				types, codes [][]string
			}{
				{"icmpTypes", "returnIcmpCodes", f.ICMPTypes, f.ICMPCodes},
				{"icmp6Types", "returnIcmp6Codes", f.ICMP6Types, f.ICMP6Codes},
			} {
				constOf := map[string]string{}
				for _, e := range fam.types {
					constOf[e[0]] = e[1]
				}
				src := section(t, icmp, fam.section)
				for _, block := range strings.Split(src, "\n  {\n")[1:] {
					tn := all(typeRE, block)
					if len(tn) != 1 {
						continue
					}
					if _, ok := constOf[tn[0]]; !ok {
						p = append(p, fmt.Sprintf("lib/icmp.ts %s: pfctl has no type %q", fam.section, tn[0]))
						continue
					}
					for _, c := range all(codeRE, block) {
						if !slices.ContainsFunc(fam.codes, func(e []string) bool { return e[0] == c && e[1] == constOf[tn[0]] }) {
							p = append(p, fmt.Sprintf("lib/icmp.ts %s: pfctl has no code %q for type %s", fam.section, c, tn[0]))
						}
					}
				}
				var codes []string
				for _, e := range fam.codes {
					codes = append(codes, e[0])
				}
				p = append(p, subset("lib/icmp.ts "+fam.ret, all(valueRE, section(t, icmp, fam.ret)), codes)...)
			}
			p = append(p, sameSet("model/types.ts timeoutNames", all(quotedRE, section(t, uiFile(t, "model/types.ts"), "timeoutNames")), f.PfTimeouts)...)
			p = append(p, sameSet("lib/pfTimeouts.ts", all(regexp.MustCompile(`(?m)^  '?([a-z0-9.]+)'?:`), uiFile(t, "lib/pfTimeouts.ts")), f.PfTimeouts)...)
			p = append(p, sameSet("FirewallStats.tsx counters", statList("const counters"), f.PfCounters)...)
			p = append(p, sameSet("FirewallStats.tsx limit counters", statList("const limitCounters"), f.LimitCounters)...)
			p = append(p, sameSet("FirewallStats.tsx pools", statList("const pools"), f.PfLimits)...)
			for _, e := range p {
				t.Error(e)
			}
		})
	}
}
