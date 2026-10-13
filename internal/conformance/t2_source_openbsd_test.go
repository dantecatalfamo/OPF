package conformance

import (
	"encoding/json"
	"testing"
)

// TestSource reads the names OPF relies on from the release's source
// (OPF_CONFORMANCE_SRC, copied in by vm.sh) and /etc/netstart, compares
// them with OPF's own lists, and saves them as source.json for the
// ordinary suite (TestSourceFacts) to compare with the UI's lists too.
func TestSource(t *testing.T) {
	owns(t)
	f := SourceFacts{Release: release()}
	parseY := srcFile(t, "sbin/pfctl/parse.y")
	if m := cvsRevRE.FindStringSubmatch(parseY); m != nil {
		f.PfctlParseY = m[1]
	}
	var err error
	if f.PfKeywords, err = yaccKeywords(parseY); err != nil {
		t.Fatal(err)
	}
	if f.NtpdKeywords, err = yaccKeywords(srcFile(t, "usr.sbin/ntpd/parse.y")); err != nil {
		t.Fatal(err)
	}
	pfctl, parser, pfvar := srcFile(t, "sbin/pfctl/pfctl.c"), srcFile(t, "sbin/pfctl/pfctl_parser.c"), srcFile(t, "sys/net/pfvar.h")
	table := func(src, decl string) [][]string {
		e, err := cTable(src, decl)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	f.PfLimits = firsts(table(pfctl, "pf_limits[]"))
	f.PfTimeouts = firsts(table(parser, "pf_timeouts[]"))
	f.ICMPTypes = table(parser, "icmp_type[]")
	f.ICMP6Types = table(parser, "icmp6_type[]")
	f.ICMPCodes = table(parser, "icmp_code[]")
	f.ICMP6Codes = table(parser, "icmp6_code[]")
	if f.PfCounters, err = cMacroStrings(pfvar, "PFRES_NAMES"); err != nil {
		t.Fatal(err)
	}
	if f.LimitCounters, err = cMacroStrings(pfvar, "LCNT_NAMES"); err != nil {
		t.Fatal(err)
	}
	if f.TrunkProtos, err = cMacroStrings(srcFile(t, "sys/net/if_trunk.h"), "TRUNK_PROTOS"); err != nil {
		t.Fatal(err)
	}
	if f.NetstartSkipped, f.NetstartLower, f.NetstartRouting, err = netstartPasses(readFile(t, "/etc/netstart")); err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(f, "", "  ")
	save(t, "source.json", string(data)+"\n")
	for _, p := range f.Problems() {
		t.Error(p)
	}
}
