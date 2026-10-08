package main

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// rcctl in the mock: the services a stock 7.9 install has (the test
// VM's), which start at boot (the VM's, then the model's settings), and
// which are running, changed by start, stop and restart.

var mockAllServices = strings.Fields("accounting amd apmd bgpd bgplgd bootparamd bpflogd check_quotas cron dhcp6leased dhcpd dhcpleased dhcrelay dhcrelay6 dvmrpd eigrpd ftpd ftpproxy ftpproxy6 hostapd hotplugd httpd identd ifstated iked inetd ipsec isakmpd iscsid ldapd ldattach ldomd ldpd library_aslr lockd lpd mopd mountd mrouted multicast nfsd npppd nsd ntpd opf ospf6d ospfd pf pflogd portmap rad radiusd rarpd rbootd relayd resolvd ripd route6d sasyncd sensorsd slaacd slowcgi smtpd sndiod snmpd spamd spamd_black spamlogd sshd statd syslogd tftpd tftpproxy unbound unwind vmd watchdogd wsmoused xenodm ypbind ypldap ypserv")

var mockOnByDefault = strings.Fields("check_quotas cron dhcpleased library_aslr ntpd opf pf pflogd resolvd slaacd smtpd sndiod sshd syslogd")

type mockServices struct {
	mu sync.Mutex
	// running overrides whether a daemon runs: what start and stop did.
	running map[string]bool
}

func (s *mockServices) on(m *pf.Model) map[string]bool {
	on := map[string]bool{}
	for _, n := range mockOnByDefault {
		on[n] = true
	}
	on["dhcpd"] = slices.ContainsFunc(m.DHCP, func(d pf.DHCPScope) bool { return d.Enabled })
	on["unbound"] = m.DNS.Enabled
	for _, st := range m.System.Services {
		on[st.Name] = st.Enabled
	}
	return on
}

func (s *mockServices) isRunning(m *pf.Model, name string) bool {
	if info, ok := pf.BaseService(name); ok && info.Kind == pf.ServiceBoot {
		return false
	}
	if r, ok := s.running[name]; ok {
		return r
	}
	// sndiod has crashed, so the page shows a daemon that failed.
	return s.on(m)[name] && name != "sndiod"
}

// handle answers rcctl; ok is false for anything else.
func (s *mockServices) handle(m *pf.Model, argv []string) (string, bool, error) {
	if len(argv) < 2 || argv[0] != "rcctl" {
		return "", false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		s.running = map[string]bool{}
	}
	on := s.on(m)
	list := func(keep func(string) bool) string {
		var out []string
		for _, n := range mockAllServices {
			if keep(n) {
				out = append(out, n)
			}
		}
		return strings.Join(out, "\n") + "\n"
	}
	switch {
	case len(argv) == 3 && argv[1] == "ls":
		switch argv[2] {
		case "all":
			return list(func(string) bool { return true }), true, nil
		case "on":
			return list(func(n string) bool { return on[n] }), true, nil
		case "started":
			return list(func(n string) bool { return s.isRunning(m, n) }), true, nil
		case "failed":
			return list(func(n string) bool {
				return on[n] && !s.isRunning(m, n) && func() bool { i, _ := pf.BaseService(n); return i.Kind != pf.ServiceBoot }()
			}), true, nil
		}
	case len(argv) == 3 && slices.Contains(mockAllServices, argv[2]):
		name := argv[2]
		switch argv[1] {
		case "get":
			flags := "NO"
			if on[name] {
				flags = ""
			}
			for _, st := range m.System.Services {
				if st.Name == name && st.Enabled && st.Flags != nil {
					flags = *st.Flags
				}
			}
			return fmt.Sprintf("%[1]s_class=daemon\n%[1]s_execdir=\n%[1]s_flags=%[2]s\n%[1]s_logger=\n%[1]s_rtable=0\n%[1]s_timeout=30\n%[1]s_user=root\n", name, flags), true, nil
		case "check":
			if s.isRunning(m, name) {
				return name + "(ok)\n", true, nil
			}
			return name + "(failed)\n", true, fmt.Errorf("exit status 1")
		case "start", "restart":
			s.running[name] = true
			return name + "(ok)\n", true, nil
		case "reload":
			if !s.isRunning(m, name) {
				return name + "(failed)\n", true, fmt.Errorf("exit status 1")
			}
			return name + "(ok)\n", true, nil
		case "stop":
			s.running[name] = false
			return name + "(ok)\n", true, nil
		}
	}
	return "", false, nil
}
