package sysinfo

import (
	"testing"
	"time"
)

// Lines unbound 1.24.2 wrote on 7.9 with logfile:, log-replies and
// log-tag-queryreply.
func TestParseUnboundLogLine(t *testing.T) {
	reply, ok := ParseUnboundLogLine("[1791387199] unbound[46658:0] reply: 127.0.0.1 a.home.test. A IN NOERROR 0.000000 1 56")
	if !ok || reply.Reply == nil || *reply.Reply != (UnboundReply{Client: "127.0.0.1", Name: "a.home.test", Type: "A", Rcode: "NOERROR", Cached: true}) || !reply.Time.Equal(time.Unix(1791387199, 0)) {
		t.Errorf("reply: %+v %+v", reply, reply.Reply)
	}
	nx, _ := ParseUnboundLogLine("[1791387199] unbound[46658:0] reply: 192.168.1.23 nope.home.test. AAAA IN NXDOMAIN 0.012000 0 43")
	if nx.Reply == nil || nx.Reply.Rcode != "NXDOMAIN" || nx.Reply.Cached {
		t.Errorf("nxdomain: %+v", nx.Reply)
	}
	rpz, ok := ParseUnboundLogLine("[1791387199] unbound[46658:0] info: rpz: applied [opf:own] blocked.example. rpz-nxdomain 127.0.0.1@45073 blocked.example. A IN")
	if !ok || rpz.RPZ == nil || rpz.RPZ.Zone != "opf:own" || rpz.RPZ.Client != "127.0.0.1" || rpz.RPZ.Name != "blocked.example" || rpz.RPZ.Action != "rpz-nxdomain" {
		t.Errorf("rpz: %+v %+v", rpz, rpz.RPZ)
	}
	warn, ok := ParseUnboundLogLine("[1791387206] unbound[46658:0] warning: continuing with less udp ports: 472")
	if !ok || warn.Level != "warning" || warn.Message != "continuing with less udp ports: 472" || warn.Reply != nil || warn.RPZ != nil {
		t.Errorf("warning: %+v", warn)
	}
	info, _ := ParseUnboundLogLine("[1791387197] unbound[46658:0] info: start of service (unbound 1.24.2).")
	if info.Level != "info" || info.RPZ != nil {
		t.Errorf("info: %+v", info)
	}
	for _, bad := range []string{
		"",
		"Oct  7 11:33:01 gw unbound: [1:0] info: x",                        // syslog's
		"[x] unbound[1:0] reply: 1 a. A IN NOERROR 0 0 1",                  // no time
		"[1791387199] named[1:0] reply: 1 a. A IN NOERROR 0 0 1",           // not unbound
		"[1791387199] unbound[1:0] reply: 127.0.0.1 a. A IN NOERROR 0.0 1", // a field short
		"[1791387199] unbound[1:0] info: rpz: applied [opf:own] nonsense",  // not an rpz line
	} {
		if u, ok := ParseUnboundLogLine(bad); ok && (u.Reply != nil || u.RPZ != nil || bad == "" || bad[0] != '[') {
			t.Errorf("%q read as %+v", bad, u)
		}
	}
}
