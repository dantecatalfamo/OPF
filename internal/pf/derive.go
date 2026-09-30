package pf

import (
	"errors"
	"fmt"
)

// What the UI shows about a model while it's being edited, worked out
// by the generators themselves so there's one implementation: the web
// process serves these (internal/web), and the offline preview build
// runs them in the browser (cmd/opfwasm). Models here haven't been
// validated, so callers go through Safe.

// Derived is everything the UI's pages show that depends on generation.
type Derived struct {
	// AutomaticNAT is the outbound NAT OPF adds on its own.
	AutomaticNAT []NATRule `json:"automaticNat"`
	// LocalNetworks is "your networks" for a split-tunnel VPN device, as
	// its configuration lists them (fixed networks only).
	LocalNetworks []string `json:"localNetworks"`
	// Rules is each rule's pf text, by rule id.
	Rules map[string]string `json:"rules"`
	// DynamicIfaces says, per interface id, whether a reference to it is
	// written in parentheses by default (it follows address changes).
	DynamicIfaces map[string]bool `json:"dynamicIfaces"`
	// SelfDynamic is the same for self.
	SelfDynamic bool `json:"selfDynamic"`
}

// Derive works out Derived for a model.
func Derive(m *Model) Derived {
	d := Derived{
		AutomaticNAT:  AutomaticNAT(m),
		LocalNetworks: LocalNetworks(m, false),
		Rules:         map[string]string{},
		DynamicIfaces: map[string]bool{},
		SelfDynamic:   ifaceDynamic(Endpoint{Type: EndpointSelf}, m),
	}
	if d.AutomaticNAT == nil {
		d.AutomaticNAT = []NATRule{}
	}
	if d.LocalNetworks == nil {
		d.LocalNetworks = []string{}
	}
	for i := range m.Firewall.Rules {
		r := &m.Firewall.Rules[i]
		d.Rules[r.ID] = GenerateRule(r, m)
	}
	for _, i := range m.Interfaces {
		d.DynamicIfaces[i.ID] = ifaceDynamic(Endpoint{Type: EndpointIface, Iface: i.ID}, m)
	}
	return d
}

// Rendered is one object's pf text as it appears in pf.conf: its
// description as a comment, and its rules.
type Rendered struct {
	Comment string   `json:"comment,omitempty"`
	Lines   []string `json:"lines"`
}

// Render returns the pf text for exactly one of a rule, an outbound NAT
// rule or a port forward, in the context of a model.
func Render(m *Model, rule *Rule, nat *NATRule, forward *PortForward) (Rendered, error) {
	n := 0
	for _, set := range []bool{rule != nil, nat != nil, forward != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return Rendered{}, errors.New("give exactly one of rule, nat and forward")
	}
	switch {
	case rule != nil:
		return Rendered{comment(rule.Description), []string{GenerateRule(rule, m)}}, nil
	case nat != nil:
		return Rendered{comment(nat.Description), []string{GenerateNATRule(nat, m)}}, nil
	default:
		return Rendered{comment(forward.Description), GeneratePortForward(forward, m)}, nil
	}
}

// Safe runs a generator on a model that may not be valid yet, turning a
// panic from a half-finished one (a static address without a prefix,
// say) into an error rather than taking the process down.
func Safe[T any](f func() T) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the configuration isn't complete enough to show: %v", r)
		}
	}()
	return f(), nil
}
