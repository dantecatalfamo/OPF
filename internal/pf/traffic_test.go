package pf

import (
	"strings"
	"testing"
)

func TestTrafficRules(t *testing.T) {
	m, _ := loadSampleModel(t)
	if strings.Contains(GeneratePfConf(m), TrafficTable) {
		t.Fatal("counted without being asked")
	}
	m.Firewall.Traffic = &TrafficAccounting{Enabled: true, Days: 7}
	conf := GeneratePfConf(m)
	if !strings.Contains(conf, "table <opf_hosts> persist counters\n") {
		t.Errorf("no table:\n%s", conf)
	}
	firstQuick := strings.Index(conf, " quick ")
	for _, i := range TrafficIfaces(m) {
		for _, want := range []string{
			"match in on $" + i.ID + " from <opf_hosts> label \"opf:traffic:" + i.ID + "\"\n",
			"match out on $" + i.ID + " to <opf_hosts> label \"opf:traffic:" + i.ID + "\"\n",
			"match in on $" + i.ID + " from ! <opf_hosts> label \"opf:traffic-unknown:" + i.ID + "\"\n",
		} {
			at := strings.Index(conf, want)
			if at < 0 || at > firstQuick {
				t.Errorf("%q missing, or after the first quick rule", want)
			}
		}
	}
	for _, i := range m.Interfaces {
		if i.Role == RoleWAN && strings.Contains(conf, "on $"+i.ID+" from <opf_hosts>") {
			t.Error("the WAN's devices counted")
		}
	}
	if k, id, ok := ParseLabel("opf:traffic-unknown:lan"); !ok || k != LabelTrafficUnknown || id != "lan" {
		t.Errorf("label %q %q %v", k, id, ok)
	}
	m.Firewall.Traffic.Days = 0
	bad := false
	for _, e := range Validate(m) {
		bad = bad || e.Path == "firewall.traffic.days"
	}
	if !bad {
		t.Error("0 days accepted")
	}
}
