package pf

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// FlowExport is a pflow(4) interface: it sends a record of each
// connection pf exports to a collector, over UDP. pf exports the states
// of rules marked pflow, or of every rule with pflow in state-defaults,
// once each ends (when pf removes the state), to every pflow interface.
type FlowExport struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Device is the interface, pflow0 and up.
	Device string `json:"device"`
	// Collector is the address the records go to, and Port its UDP
	// port.
	Collector string `json:"collector"`
	Port      int    `json:"port"`
	// Source is the interface whose fixed IPv4 address they're sent
	// from (flowsrc), or empty for the address the route to the
	// collector picks.
	Source string `json:"source,omitempty"`
	// Version is the record format: 5 (NetFlow v5, IPv4 connections
	// only) or 10 (IPFIX).
	Version int `json:"version"`
}

// MaxFlowExports caps the pflow interfaces a model has.
const MaxFlowExports = 8

// The record formats pflow has (PFLOW_PROTOS in net/if_pflow.h).
const (
	FlowNetFlow5 = 5
	FlowIPFIX    = 10
)

var pflowDeviceRE = regexp.MustCompile(`^pflow[0-9]+$`)

// flowDst is a collector as flowdst takes it: address:port, an IPv6
// address in brackets (ifconfig's pflow_addr).
func flowDst(addr string, port int) string {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), uint16(port)).String()
}

// GenerateHostnamePflow is a flow export's hostname.pflowN. Every
// setting is written each time, -flowsrc too, since netstart on an
// interface that exists only changes what the file says.
func GenerateHostnamePflow(e *FlowExport, m *Model) string {
	src := "-flowsrc"
	if a := flowSource(e, m); a != "" {
		src = "flowsrc " + a
	}
	state := "down"
	if e.Enabled {
		state = "up"
	}
	return strings.Join([]string{
		header,
		fmt.Sprintf("description \"%s\"", e.Name),
		fmt.Sprintf("%s flowdst %s pflowproto %d", src, flowDst(e.Collector, e.Port), e.Version),
		state,
	}, "\n") + "\n"
}

func (v *validator) flowExports() {
	exports := v.m.Firewall.FlowExports
	if len(exports) > MaxFlowExports {
		v.fail("firewall.flowExports", "at most %d", MaxFlowExports)
	}
	ids, devices := map[string]bool{}, map[string]bool{}
	for i, e := range exports {
		p := at("firewall.flowExports", i)
		v.re(p+".id", e.ID, idRE, "id")
		v.unique(p+".id", ids, e.ID, "flow export id")
		v.re(p+".name", e.Name, plainNameRE, "name (letters, digits, spaces, _ . -)")
		if v.re(p+".device", e.Device, pflowDeviceRE, "pflow device (like pflow0)") && len(e.Device) > 15 {
			v.fail(p+".device", "is longer than 15 characters")
		}
		v.unique(p+".device", devices, e.Device, "device")
		if v.ifaceByDevice(e.Device) {
			v.fail(p+".device", "%s is an interface's device already", e.Device)
		}
		v.oneOf(p+".version", strconv.Itoa(e.Version), strconv.Itoa(FlowNetFlow5), strconv.Itoa(FlowIPFIX))
		v.intRange(p+".port", e.Port, 1, 65535)
		dst := v.addr(p+".collector", e.Collector, false)
		if dst.IsValid() && dst.IsUnspecified() {
			v.fail(p+".collector", "%q is no address to send to", e.Collector)
		}
		if e.Source == "" {
			continue
		}
		// pflow binds its socket to the address when the interface is
		// set up, which fails for one the firewall doesn't have yet.
		switch f := v.iface(e.Source); {
		case f == nil:
			v.fail(p+".source", "no interface %q", e.Source)
		case dst.IsValid() && !dst.Is4():
			v.fail(p+".source", "an IPv6 collector is sent to from the address its route picks")
		case f.IPv4.Mode != IPv4Static:
			v.fail(p+".source", "%s has no fixed address to send from", f.Name)
		case !f.Enabled:
			v.fail(p+".source", "%s is turned off", f.Name)
		}
	}
}

func (v *validator) ifaceByDevice(dev string) bool {
	return slices.ContainsFunc(v.m.Interfaces, func(f Iface) bool { return f.Device == dev })
}

// flowSource is the address a flow export sends from, or "".
func flowSource(e *FlowExport, m *Model) string {
	for _, f := range m.Interfaces {
		if f.ID == e.Source && e.Source != "" {
			return f.IPv4.Address
		}
	}
	return ""
}

// parseHostnamePflow reads a hostname.pflowN word by word, as ifconfig
// takes it; ok is false for a setting a FlowExport doesn't have, or no
// collector.
func parseHostnamePflow(content string) (e FlowExport, ok bool) {
	e.Enabled, e.Version = true, FlowNetFlow5 // the kernel's defaults
	dst := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if c := strings.IndexByte(line, '#'); c >= 0 && !strings.Contains(line[:c], `"`) {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		line = ifWordsRE.ReplaceAllString(line, " ")
		if sub := ifDescRE.FindStringSubmatch(line); sub != nil {
			e.Name = sub[1] + sub[2]
			continue
		}
		w := strings.Fields(line)
		for i := 0; i < len(w); i++ {
			arg := func() string {
				if i+1 < len(w) {
					i++
					return w[i]
				}
				return ""
			}
			switch w[i] {
			case "up":
				e.Enabled = true
			case "down":
				e.Enabled = false
			case "-flowsrc":
				e.Source = ""
			case "flowsrc":
				a, err := netip.ParseAddr(arg())
				if err != nil || !a.Is4() {
					return e, false
				}
				e.Source = a.String()
			case "flowdst":
				ap, err := netip.ParseAddrPort(arg())
				if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
					return e, false
				}
				e.Collector, e.Port, dst = ap.Addr().Unmap().String(), int(ap.Port()), true
			case "pflowproto":
				n, err := strconv.Atoi(arg())
				if err != nil || n != FlowNetFlow5 && n != FlowIPFIX {
					return e, false
				}
				e.Version = n
			default:
				return e, false
			}
		}
	}
	return e, dst
}

// importFlowExports reads every hostname.pflowN. One with a setting a
// flow export doesn't have, or no collector, is left as it is.
func importFlowExports(m *Model, src ImportSources) []ImportNote {
	var notes []ImportNote
	var paths []string
	for p := range src.Files {
		if sub := ifFileRE.FindStringSubmatch(p); sub != nil && pflowDeviceRE.MatchString(sub[1]) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	for _, p := range paths {
		dev := ifFileRE.FindStringSubmatch(p)[1]
		e, ok := parseHostnamePflow(src.Files[p])
		if ok && e.Source != "" {
			// From the address to the interface that has it.
			addr := e.Source
			e.Source = ""
			for _, f := range m.Interfaces {
				if f.Enabled && f.IPv4.Mode == IPv4Static && f.IPv4.Address == addr {
					e.Source = f.ID
				}
			}
			ok = e.Source != ""
		}
		if !ok || len(m.Firewall.FlowExports) == MaxFlowExports {
			notes = append(notes, ImportNote{File: p, Kind: NoteLeft, Message: "a pflow interface OPF can't take over (no collector, or a setting OPF doesn't have): left as it is"})
			continue
		}
		e.ID, e.Device = dev, dev
		if !plainNameRE.MatchString(e.Name) {
			if e.Name != "" {
				notes = append(notes, ImportNote{File: p, Kind: NoteLost, Text: fmt.Sprintf("description %q", e.Name), Message: "OPF gives every flow export a description: its name"})
			}
			e.Name = dev
		}
		m.Firewall.FlowExports = append(m.Firewall.FlowExports, e)
		notes = append(notes, ImportNote{File: p, Kind: NoteModel, Message: "a flow export to " + flowDst(e.Collector, e.Port)})
	}
	return notes
}
