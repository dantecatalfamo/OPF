package privsep

import (
	"net"
	"net/rpc"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

type Echo struct{}

type Zeros struct {
	Run   *diag.Run
	Iface *appliance.InterfaceState
}

func (Echo) Echo(a Zeros, r *Zeros) error {
	*r = a
	return nil
}

// Zero values, pointers to zero above all, cross the connection intact:
// gob alone would turn an exit status of 0 into "didn't exit" and 0 bps
// into "unknown".
func TestCodecKeepsZeros(t *testing.T) {
	a, b := net.Pipe()
	srv := rpc.NewServer()
	if err := srv.Register(Echo{}); err != nil {
		t.Fatal(err)
	}
	go srv.ServeCodec(newServerCodec(a))
	client := rpc.NewClientWithCodec(newClientCodec(b))
	defer client.Close()

	zero, zeroF, zeroI := 0, 0.0, int64(0)
	in := Zeros{
		Run: &diag.Run{ID: "x", ExitCode: &zero, Lines: []string{}},
		Iface: &appliance.InterfaceState{
			Interface: sysinfo.Interface{Name: "enc0", WireGuard: &sysinfo.WireGuard{Peers: []sysinfo.WGPeer{{PublicKey: "k", HandshakeAgo: &zeroI}}}},
			Counters:  &sysinfo.Counters{}, RxBps: &zeroF, TxBps: &zeroF,
		},
	}
	var out Zeros
	if err := client.Call("Echo.Echo", in, &out); err != nil {
		t.Fatal(err)
	}
	if out.Run == nil || out.Run.ExitCode == nil || *out.Run.ExitCode != 0 {
		t.Errorf("exit code: %+v", out.Run)
	}
	i := out.Iface
	if i == nil || i.RxBps == nil || i.TxBps == nil || i.Counters == nil {
		t.Fatalf("interface: %+v", i)
	}
	if p := i.WireGuard.Peers[0]; p.HandshakeAgo == nil || *p.HandshakeAgo != 0 {
		t.Errorf("handshake: %+v", p)
	}
}

type ActivityEcho struct{}

func (ActivityEcho) Echo(a appliance.DNSActivity, r *appliance.DNSActivity) error {
	*r = a
	return nil
}

func (ActivityEcho) Device(a appliance.DNSDeviceActivity, r *appliance.DNSDeviceActivity) error {
	*r = a
	return nil
}

// DNS activity's views embed the store's: they cross whole.
func TestCodecCarriesDNSActivity(t *testing.T) {
	a, b := net.Pipe()
	srv := rpc.NewServer()
	if err := srv.Register(ActivityEcho{}); err != nil {
		t.Fatal(err)
	}
	go srv.ServeCodec(newServerCodec(a))
	client := rpc.NewClientWithCodec(newClientCodec(b))
	defer client.Close()

	in := appliance.DNSActivity{Enabled: true, PerDevice: true, Days: 7,
		Summary: &activity.Summary{
			Total:   activity.Counts{Queries: 3, Blocked: 1},
			ByList:  map[string]int64{"ads": 1},
			Names:   []activity.Item{{Name: "example.com", Count: 2}},
			Devices: []activity.DeviceSummary{{Key: "mac:aa", Address: "192.168.1.5", Counts: activity.Counts{Queries: 3}}},
		},
		DeviceInfo: map[string]appliance.ActivityDevice{"mac:aa": {Kind: "device", Name: "laptop", MAC: "aa"}},
	}
	var out appliance.DNSActivity
	if err := client.Call("ActivityEcho.Echo", in, &out); err != nil {
		t.Fatal(err)
	}
	if !out.PerDevice || out.Summary == nil || out.Total.Queries != 3 || out.ByList["ads"] != 1 || out.Names[0].Name != "example.com" ||
		out.Devices[0].Address != "192.168.1.5" || out.DeviceInfo["mac:aa"].Name != "laptop" {
		t.Errorf("%+v %+v", out, out.Summary)
	}
	dev := appliance.DNSDeviceActivity{ActivityDevice: appliance.ActivityDevice{Kind: "vpn", Name: "phone"},
		DeviceActivity: &activity.DeviceActivity{Key: "vpn:p1", Total: activity.Counts{NXDomain: 4}}}
	var dout appliance.DNSDeviceActivity
	if err := client.Call("ActivityEcho.Device", dev, &dout); err != nil {
		t.Fatal(err)
	}
	if dout.Name != "phone" || dout.DeviceActivity == nil || dout.Key != "vpn:p1" || dout.Total.NXDomain != 4 {
		t.Errorf("%+v", dout)
	}
}
