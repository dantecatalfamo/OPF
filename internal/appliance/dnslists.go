package appliance

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// DNS blocklists: lists of names the resolver blocks, downloaded like
// pf's lists (fetch.go) in whatever format they're published in, kept
// as OPF's own copy of the names (pf.DNSListsDir), and written as an
// RPZ zone per answer (pf.DNSListZonePath) that unbound.conf names.

// DomainList is what a downloaded list says: the names to block and to
// let through (adblock exceptions, RPZ passthru), "example.com" or
// "*.example.com", and the lines left out, by why.
type DomainList struct {
	Blocked []string
	Allowed []string
	Skipped map[string]int
}

// Why a line of a list was left out, as the page says it.
const (
	skipCosmetic = "element hiding (not something DNS can do)"
	skipPath     = "a path or pattern (DNS only sees names)"
	skipOptions  = "narrowed by options such as $third-party"
	skipInvalid  = "not a name"
	skipAddress  = "an address, not a name"
)

// Names hosts files map to themselves, not ones to block.
var hostsSelf = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// parseDomainList reads a blocklist in any of the formats DNS blockers
// use, line by line, so a list can mix them:
//
//	0.0.0.0 ads.example.com         hosts file: that name
//	ads.example.com                 a plain name
//	||ads.example.com^              adblock: the name and everything under it
//	@@||ok.example.com^             adblock exception: let it through
//	ads.example.com CNAME .         RPZ: block; "CNAME rpz-passthru." lets through
//
// Comments (#, !, [Adblock ...]) and zone boilerplate are ignored. What
// DNS can't do (element hiding, paths, rules narrowed by options) is
// counted and left out.
func parseDomainList(lines []string) DomainList {
	res := DomainList{Skipped: map[string]int{}}
	blocked, allowed := map[string]bool{}, map[string]bool{}
	add := func(set map[string]bool, names ...string) {
		for _, n := range names {
			set[strings.ToLower(strings.TrimSuffix(n, "."))] = true
		}
	}
	for _, raw := range lines {
		l := strings.TrimSpace(raw)
		switch {
		case l == "", l[0] == '!', l[0] == '[', strings.HasPrefix(l, "$"), strings.HasPrefix(l, ";"), strings.HasPrefix(l, "@ "), strings.HasPrefix(l, "@\t"):
			continue
		case strings.Contains(l, "##"), strings.Contains(l, "#@#"), strings.Contains(l, "#?#"), strings.Contains(l, "#$#"):
			res.Skipped[skipCosmetic]++
			continue
		case l[0] == '#':
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		// RPZ: owner [ttl] [class] CNAME target. First, since owners can
		// be wildcards.
		if f := strings.Fields(l); len(f) >= 3 && strings.EqualFold(f[len(f)-2], "CNAME") {
			owner, target := f[0], f[len(f)-1]
			switch {
			case !pf.IsBlockName(owner) || isAddr(strings.TrimPrefix(owner, "*.")):
				res.Skipped[skipInvalid]++
			case target == "." || target == "*.":
				add(blocked, owner)
			case strings.EqualFold(target, "rpz-passthru."):
				add(allowed, owner)
			default:
				res.Skipped[skipInvalid]++ // a redirect OPF doesn't follow
			}
			continue
		}
		// A wildcard name, as some lists write them.
		if f := strings.Fields(l); len(f) == 1 && strings.HasPrefix(f[0], "*.") && pf.IsBlockName(f[0]) && strings.Count(f[0], ".") >= 2 {
			add(blocked, f[0])
			continue
		}
		// Adblock rules.
		if rule, ok := strings.CutPrefix(l, "@@"); ok || strings.HasPrefix(l, "||") || strings.ContainsAny(l, "/|^*$") {
			set := blocked
			if ok {
				set = allowed
			}
			body, anchored := strings.CutPrefix(rule, "||")
			// $important only raises a rule's priority; any other option
			// narrows when it applies, which DNS can't tell.
			if b, opts, has := strings.Cut(body, "$"); has {
				if opts != "important" {
					res.Skipped[skipOptions]++
					continue
				}
				body = b
			}
			name, whole := strings.CutSuffix(strings.TrimSuffix(body, "|"), "^")
			if !anchored || !whole || strings.ContainsAny(name, "/*:^|") {
				res.Skipped[skipPath]++
				continue
			}
			switch {
			case isAddr(name):
				res.Skipped[skipAddress]++
			case !pf.IsBlockName(name) || !strings.Contains(name, "."):
				res.Skipped[skipInvalid]++
			default:
				add(set, name, "*."+name)
			}
			continue
		}
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && isAddr(f[0]):
			// hosts: address name [name...]
			for _, n := range f[1:] {
				switch {
				case hostsSelf[strings.ToLower(n)]:
				case isAddr(n):
					res.Skipped[skipAddress]++
				case pf.IsBlockName(n) && !strings.HasPrefix(n, "*.") && strings.Contains(n, "."):
					add(blocked, n)
				default:
					res.Skipped[skipInvalid]++
				}
			}
		case len(f) == 1 && isAddr(f[0]):
			res.Skipped[skipAddress]++
		case len(f) == 1 && pf.IsBlockName(f[0]) && strings.Contains(f[0], "."):
			add(blocked, f[0])
		case len(f) >= 2 && (strings.EqualFold(f[len(f)-2], "SOA") || strings.EqualFold(f[1], "NS") || strings.EqualFold(f[len(f)-2], "NS")):
			// zone boilerplate
		case len(f) == 1 && strings.ContainsAny(f[0], "&=?%"):
			res.Skipped[skipPath]++ // part of a URL, from an adblock list
		default:
			res.Skipped[skipInvalid]++
		}
	}
	// A name a list both blocks and lets through is let through.
	for n := range allowed {
		delete(blocked, n)
	}
	res.Blocked, res.Allowed = sorted(blocked), sorted(allowed)
	return res
}

func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// fetchDNSList downloads a blocklist and reads the names in it.
func (m *Manager) fetchDNSList(ctx context.Context, url string) (DomainList, error) {
	lines, err := m.fetchLines(ctx, url)
	if err != nil {
		return DomainList{}, err
	}
	res := parseDomainList(lines)
	if len(res.Blocked) == 0 {
		skipped := 0
		for _, n := range res.Skipped {
			skipped += n
		}
		return res, emptyListError(skipped, "a name to block", "names to block")
	}
	return res, nil
}

// OPF's copy of a list's names: a header, "# skipped <n> <why>" lines,
// then "block <name>" and "allow <name>". The zones are written from it.
func (m *Manager) dnsNamesPath(id string) string {
	return m.store.SystemPath(filepath.Join(pf.DNSListsDir, id))
}

// writeAtomic writes a file whole or not at all.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// saveDNSList keeps a downloaded list and rewrites every zone written
// from it before, so whichever unbound.conf names is up to date.
func (m *Manager) saveDNSList(l pf.DNSBlocklist, res DomainList) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Downloaded by OPF from %s at %s\n", l.URL, time.Now().UTC().Format(time.RFC3339))
	whys := make([]string, 0, len(res.Skipped))
	for why := range res.Skipped {
		whys = append(whys, why)
	}
	sort.Strings(whys)
	for _, why := range whys {
		fmt.Fprintf(&b, "# skipped %d %s\n", res.Skipped[why], why)
	}
	for _, n := range res.Blocked {
		b.WriteString("block " + n + "\n")
	}
	for _, n := range res.Allowed {
		b.WriteString("allow " + n + "\n")
	}
	if err := writeAtomic(m.dnsNamesPath(l.ID), []byte(b.String()), 0644); err != nil {
		return err
	}
	for _, a := range []pf.BlockAnswer{pf.BlockAnswerNull, pf.BlockAnswerNXDomain} {
		if exists(m.store.SystemPath(pf.DNSListZonePath(l.ID, a))) {
			if err := m.writeDNSZone(l.ID, a, res); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) writeDNSZone(id string, a pf.BlockAnswer, res DomainList) error {
	return writeAtomic(m.store.SystemPath(pf.DNSListZonePath(id, a)), []byte(pf.RPZZone(res.Blocked, res.Allowed, a)), 0644)
}

// readDNSList reads OPF's copy of a list back.
func (m *Manager) readDNSList(id string) (DomainList, time.Time, error) {
	res := DomainList{Skipped: map[string]int{}}
	path := m.dnsNamesPath(id)
	fi, err := os.Stat(path)
	if err != nil {
		return res, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return res, time.Time{}, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(l, "# skipped "); ok {
			if n, why, ok := strings.Cut(rest, " "); ok {
				if x, err := strconv.Atoi(n); err == nil {
					res.Skipped[why] = x
				}
			}
		} else if n, ok := strings.CutPrefix(l, "block "); ok {
			res.Blocked = append(res.Blocked, n)
		} else if n, ok := strings.CutPrefix(l, "allow "); ok {
			res.Allowed = append(res.Allowed, n)
		}
	}
	return res, fi.ModTime(), nil
}

// prepareDNSLists downloads the enabled lists a model has that haven't
// been, and writes each one's zone for the model's answer if it isn't
// there: unbound.conf will name it.
func (m *Manager) prepareDNSLists(ctx context.Context, model *pf.Model) error {
	for _, l := range model.DNS.Blocklists {
		if !l.Enabled {
			continue
		}
		res, _, err := m.readDNSList(l.ID)
		if err != nil {
			if res, err = m.fetchDNSList(ctx, l.URL); err != nil {
				return &Error{Code: CodeCheckFailed, Message: fmt.Sprintf("couldn't download the DNS blocklist %s from %s: %s; nothing was changed", l.Name, l.URL, err),
					Details: []Detail{{Path: filepath.Join(pf.DNSListsDir, l.ID), Message: err.Error()}}}
			}
			if err := m.saveDNSList(l, res); err != nil {
				return err
			}
		}
		if !exists(m.store.SystemPath(pf.DNSListZonePath(l.ID, model.DNS.BlockAnswer))) {
			if err := m.writeDNSZone(l.ID, model.DNS.BlockAnswer, res); err != nil {
				return err
			}
		}
	}
	return nil
}

// DNSListStatus is a DNS blocklist's download.
type DNSListStatus struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	URL     string     `json:"url"`
	Enabled bool       `json:"enabled"`
	Fetched *time.Time `json:"fetched,omitempty"` // nil: not downloaded yet
	Blocked int        `json:"blocked"`
	Allowed int        `json:"allowed"`
	// Skipped counts the lines left out, by why.
	Skipped map[string]int `json:"skipped"`
	Refresh RefreshState   `json:"refresh"`
	Warning string         `json:"warning,omitempty"`
}

// DNSLists returns the applied configuration's DNS blocklists.
func (m *Manager) DNSLists() ([]DNSListStatus, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	out := []DNSListStatus{}
	for _, l := range model.DNS.Blocklists {
		out = append(out, m.dnsListStatus(l))
	}
	return out, nil
}

func (m *Manager) dnsListStatus(l pf.DNSBlocklist) DNSListStatus {
	st := DNSListStatus{ID: l.ID, Name: l.Name, URL: l.URL, Enabled: l.Enabled, Skipped: map[string]int{}}
	if res, t, err := m.readDNSList(l.ID); err == nil {
		st.Fetched = &t
		st.Blocked, st.Allowed, st.Skipped = len(res.Blocked), len(res.Allowed), res.Skipped
	}
	st.Refresh = m.refreshState(dnsKey(l.ID), st.Fetched, l.RefreshHours)
	return st
}

// RefreshDNSList downloads a blocklist again and reloads its zone in
// unbound. If the download fails, the list already there stays in use.
func (m *Manager) RefreshDNSList(id string) (*DNSListStatus, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	for _, l := range model.DNS.Blocklists {
		if l.ID == id {
			warning, err := m.refreshDNSList(context.Background(), l)
			if err != nil {
				return nil, errorf(CodeCheckFailed, "couldn't download %s: %s; the list already there is still in use", l.URL, err)
			}
			st := m.dnsListStatus(l)
			st.Warning = warning
			return &st, nil
		}
	}
	return nil, errorf(CodeNotFound, "no DNS blocklist %q in the applied configuration", id)
}

func (m *Manager) refreshDNSList(ctx context.Context, l pf.DNSBlocklist) (warning string, err error) {
	defer func() { m.noteRefresh(dnsKey(l.ID), err) }()
	res, err := m.fetchDNSList(ctx, l.URL)
	if err != nil {
		return "", err
	}
	if err := m.saveDNSList(l, res); err != nil {
		return "", err
	}
	if !l.Enabled {
		return "", nil
	}
	// Just this zone, from its file: a full reload would flush the cache
	// and the names DHCP leases have.
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if out, err := m.actions().Run(ctx, "unbound-control", "-c", "/var/unbound/etc/unbound.conf", "auth_zone_reload", pf.DNSListZoneName(l.ID)); err != nil {
		return "downloaded, but unbound didn't reload it: " + firstLine(string(out)), nil
	}
	return "", nil
}
