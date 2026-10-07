package appliance

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// A config.json from before the interface gateway moved to Routing
// still loads, with it moved; one staged by a page from before is moved
// too, and the file written doesn't have it.
func TestOldInterfaceGateway(t *testing.T) {
	old := strings.Replace(mustRead(t, "../../ui/src/model/sample-model.json"),
		`"ipv4": {
        "mode": "dhcp"
      }`, `"ipv4": {"mode": "static", "address": "203.0.113.10", "prefix": 24, "gateway": "203.0.113.1"}`, 1)
	m, err := decodeModel([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if m.Interfaces[0].IPv4.Gateway != "" || m.Routing.Gateways[0].Address != "203.0.113.1" {
		t.Fatalf("not moved: %+v %+v", m.Interfaces[0].IPv4, m.Routing.Gateways[0])
	}

	e := newEnv(t, time.Minute)
	live := e.live()
	mm := live.Model
	prefix := 24
	mm.Interfaces[0].IPv4 = pf.IPv4Config{Mode: pf.IPv4Static, Address: "203.0.113.10", Prefix: &prefix, Gateway: "203.0.113.1"}
	st, err := e.m.Stage(StageRequest{Base: live.Version, Model: mm})
	if err != nil {
		t.Fatalf("stage: %v %+v", err, AsError(err).Details)
	}
	paths := map[string]string{}
	for _, c := range st.Changes {
		paths[c.Path] = c.Diff
	}
	if !strings.Contains(paths["/etc/mygate"], "+203.0.113.1") {
		t.Errorf("no mygate: %+v", st.Changes)
	}
	if strings.Contains(paths["/var/opf/config.json"], `"gateway": "203.0.113.1"`) {
		t.Error("config.json still has the interface's gateway")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
