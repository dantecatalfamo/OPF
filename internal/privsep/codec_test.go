package privsep

import (
	"net"
	"net/rpc"
	"testing"

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
