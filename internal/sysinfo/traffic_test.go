package sysinfo

import "testing"

func TestParsePfTableCounters(t *testing.T) {
	c := ParsePfTableCounters(readCaptured(t, "pfctl_-t_opf_hosts_-T_show_-v.txt"))
	want := map[string]TableCounters{
		"192.168.50.2": {SentPackets: 2957, SentBytes: 4348092, ReceivedPackets: 2106, ReceivedBytes: 125920},
		"192.168.60.2": {SentPackets: 1034, SentBytes: 53780, ReceivedPackets: 1472, ReceivedBytes: 2173708},
	}
	if len(c) != 2 || c["192.168.50.2"] != want["192.168.50.2"] || c["192.168.60.2"] != want["192.168.60.2"] {
		t.Errorf("%+v", c)
	}
	// An address with no counters yet (just added) is there, at zero.
	if c := ParsePfTableCounters("   192.168.50.9\n"); len(c) != 1 || c["192.168.50.9"] != (TableCounters{}) {
		t.Errorf("%+v", c)
	}
}

func TestParsePfLabels(t *testing.T) {
	l := ParsePfLabels(readCaptured(t, "pfctl_-s_labels.txt"))
	if _, ok := l["opf:auto-nat:lan"]; !ok || len(l) < 5 {
		t.Errorf("%d labels: %+v", len(l), l)
	}
	for name := range l {
		if name == "ID" {
			t.Error("a header line read as a label")
		}
	}
}
