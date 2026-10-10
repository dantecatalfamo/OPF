package conformance

// Flow export: the everything model's pflow interfaces as ifconfig has
// them, and pflow's records reaching a collector.

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// TestFlowExport: each hostname.pflowN set what OPF wrote, and a
// connection that ends reaches the suite's collector (pflow0, on
// loopback, which pf doesn't filter) as an IPFIX record.
func TestFlowExport(t *testing.T) {
	configured(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(flowCollector), Port: flowPort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, e := range modelNamed(&recorder{T: t}, "everything").Firewall.FlowExports {
		out := must(t, "ifconfig", e.Device)
		want := "\tpflow: "
		if e.Source != "" {
			want += "sender: " + lanIface(devices).IPv4.Address + " "
		}
		dst := e.Collector + ":"
		if strings.Contains(e.Collector, ":") {
			dst = "[" + e.Collector + "]:"
		}
		want += "receiver: " + dst + strconv.Itoa(e.Port) + " version: " + strconv.Itoa(e.Version) + "\n"
		if !strings.Contains(out, want) {
			t.Errorf("ifconfig %s has no %q:\n%s", e.Device, want, out)
		}
		// pflow is running once it's up with a receiver set.
		flags := strings.SplitN(out, "\n", 2)[0]
		if running := strings.Contains(flags, "UP,RUNNING"); running != e.Enabled {
			t.Errorf("%s turned on %v, but its flags are %s", e.Device, e.Enabled, flags)
		}
	}

	// A connection that ends: the client's ping to the firewall, its
	// state killed. pflow sends a record as pf removes the state, at
	// most 30 seconds later (PFLOW_TIMEOUT).
	run("route", "-T"+clientRdom, "exec", "ping", "-c", "1", clientRoute)
	must(t, "pfctl", "-k", clientAddr)
	buf := make([]byte, 65536)
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no IPFIX record of the client's connection within a minute: %v", err)
		}
		b := buf[:n]
		if n < 20 {
			t.Fatalf("a %d-byte packet is too short for IPFIX: %x", n, b)
		}
		// The message header, then the first set's id: 2 for templates,
		// 256 and up for records (net/if_pflow.h).
		if v := binary.BigEndian.Uint16(b[0:2]); v != pf.FlowIPFIX {
			t.Fatalf("version %d in the header, want %d", v, pf.FlowIPFIX)
		}
		if set := binary.BigEndian.Uint16(b[16:18]); set >= 256 {
			save(t, "pflow_ipfix_record.txt", hex.Dump(b))
			return
		}
	}
}
