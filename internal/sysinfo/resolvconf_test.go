package sysinfo

import (
	"reflect"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	// As on the VM: resolvd's line from the WAN's lease.
	rc := ParseResolvConf("nameserver 100.64.1.2 # resolvd: vio0\nlookup file bind\n")
	want := ResolvConf{Servers: []Nameserver{{Address: "100.64.1.2", From: "vio0"}}, Lookup: []string{"file", "bind"}}
	if !reflect.DeepEqual(rc, want) {
		t.Errorf("%+v", rc)
	}
	// Written by hand, more than the C library reads, no lookup line.
	rc = ParseResolvConf("# mine\nnameserver 9.9.9.9\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 192.0.2.1\nsearch example.com\n")
	if len(rc.Servers) != 4 || rc.Servers[0].From != "" || rc.Servers[2].Unused || !rc.Servers[3].Unused || !reflect.DeepEqual(rc.Lookup, []string{"file", "bind"}) {
		t.Errorf("%+v", rc)
	}
	if rc := ParseResolvConf(""); len(rc.Servers) != 0 || rc.Servers == nil {
		t.Errorf("empty: %+v", rc)
	}
}
