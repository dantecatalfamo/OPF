package appliance

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// What pf's tables hold now: the addresses in a table alias (a dynamic
// table a rule's overload fills, or a downloaded list), finding an
// address across all of them, and taking addresses out of a dynamic
// table or adding them by hand. Only the live model's table and URL
// aliases are read, never pf's other tables.

// TableEntriesRequest asks for a page of a table's entries, those
// containing Query when it's set.
type TableEntriesRequest struct {
	Table  string `json:"table"`
	Query  string `json:"query,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"` // 100 when 0; at most 1000
}

// TableEntry is one address or network in a table.
type TableEntry struct {
	Address string `json:"address"`
	// Negated entries (!192.0.2.128/25) take addresses out of a wider
	// one.
	Negated bool `json:"negated,omitempty"`
	// Added is when pf last cleared its statistics: when it was added,
	// for an address a rule or OPF put there. Only for dynamic tables.
	Added *time.Time `json:"added,omitempty"`
	// Expires is when OPF takes it out (pf.Alias.ExpireMinutes).
	Expires *time.Time `json:"expires,omitempty"`
}

// TableEntries is a page of what a table holds.
type TableEntries struct {
	Table string `json:"table"`
	// Kind: "dynamic" (pf.AliasTable) or "list" (pf.AliasURL).
	Kind string `json:"kind"`
	// Loaded is false when pf has no such table yet (not applied).
	Loaded bool `json:"loaded"`
	// Total is every entry; Matching those Query matched.
	Total         int          `json:"total"`
	Matching      int          `json:"matching"`
	Entries       []TableEntry `json:"entries"`
	ExpireMinutes *int         `json:"expireMinutes,omitempty"`
	// FilledBy are the rules whose overload adds to it.
	FilledBy []TableRule `json:"filledBy"`
}

// TableRule is a rule, by id and description.
type TableRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

const (
	tablePage    = 100
	tablePageMax = 1000
	// tableChangeMax is the most addresses one change may name.
	tableChangeMax = 256
)

// tableAlias is the live model's table or URL alias called name.
func (m *Manager) tableAlias(name string) (*pf.Model, *pf.Alias, error) {
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, nil, apiError(err)
	}
	for i := range model.Firewall.Aliases {
		a := &model.Firewall.Aliases[i]
		if a.Name == name && (a.Type == pf.AliasTable || a.Type == pf.AliasURL) {
			return model, a, nil
		}
	}
	return nil, nil, errorf(CodeNotFound, "no table or downloaded list called %q in the applied configuration", name)
}

// tableShow reads a table's entries; loaded is false when pf has none.
// With verbose, each has when its statistics were last cleared.
func (m *Manager) tableShow(name string, verbose bool) (entries []TableEntry, loaded bool, err error) {
	argv := []string{"pfctl", "-t", name, "-T", "show"}
	if verbose {
		argv = append(argv, "-v")
	}
	out, err := m.read(argv...)
	if err != nil {
		if strings.Contains(out, "Table does not exist") {
			return []TableEntry{}, false, nil
		}
		return nil, false, fmt.Errorf("pfctl -t %s -T show: %v", name, err)
	}
	return parseTableShow(out, time.Local), true, nil
}

// parseTableShow reads pfctl -T show [-v]:
//
//	   192.0.2.0/24
//		Cleared:     Thu Oct  8 00:45:58 2026
//	  !192.0.2.128/25
func parseTableShow(out string, loc *time.Location) []TableEntry {
	entries := []TableEntry{}
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, "\t") {
			a := strings.TrimSpace(l)
			e := TableEntry{Address: a}
			if strings.HasPrefix(a, "!") {
				e.Address, e.Negated = strings.TrimSpace(a[1:]), true
			}
			entries = append(entries, e)
			continue
		}
		if len(entries) == 0 {
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Cleared:"); ok {
			if t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(v), loc); err == nil {
				entries[len(entries)-1].Added = &t
			}
		}
	}
	return entries
}

// TableEntries is a page of a table's entries.
func (m *Manager) TableEntries(req TableEntriesRequest) (*TableEntries, error) {
	model, a, err := m.tableAlias(req.Table)
	if err != nil {
		return nil, err
	}
	out := &TableEntries{Table: a.Name, Kind: "dynamic", Entries: []TableEntry{}, FilledBy: []TableRule{}, ExpireMinutes: a.ExpireMinutes}
	if a.Type == pf.AliasURL {
		out.Kind = "list"
	}
	for _, r := range model.Firewall.Rules {
		if r.IsForm() && r.State != nil && r.State.Overload == a.Name {
			out.FilledBy = append(out.FilledBy, TableRule{ID: r.ID, Description: r.Description})
		}
	}
	// A downloaded list's entries were all loaded together: when isn't
	// worth -v's three lines an entry.
	all, loaded, err := m.tableShow(a.Name, a.Type == pf.AliasTable)
	if err != nil {
		return nil, errorf(CodeInternal, "%v", err)
	}
	out.Loaded, out.Total = loaded, len(all)
	q := strings.TrimSpace(req.Query)
	matching := all
	if q != "" {
		matching = nil
		for _, e := range all {
			if strings.Contains(e.Address, q) {
				matching = append(matching, e)
			}
		}
	}
	out.Matching = len(matching)
	// Newest first in a dynamic table; a list in pf's order.
	if a.Type == pf.AliasTable {
		sort.SliceStable(matching, func(i, j int) bool {
			ai, aj := matching[i].Added, matching[j].Added
			return ai != nil && (aj == nil || ai.After(*aj))
		})
	}
	limit := req.Limit
	if limit <= 0 {
		limit = tablePage
	}
	limit = min(limit, tablePageMax)
	start := min(max(req.Offset, 0), len(matching))
	for _, e := range matching[start:min(start+limit, len(matching))] {
		if a.ExpireMinutes != nil && e.Added != nil {
			t := e.Added.Add(time.Duration(*a.ExpireMinutes) * time.Minute)
			e.Expires = &t
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// TableMatch is a table an address is in, and the entry that put it
// there.
type TableMatch struct {
	Table string `json:"table"`
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
	// Added and Expires as for the entry, in a dynamic table.
	Added   *time.Time `json:"added,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`
	// UsedBy are the rules that name the table.
	UsedBy []TableRule `json:"usedBy"`
}

// TableFind is every table alias an address is in.
type TableFind struct {
	Address string       `json:"address"`
	Tables  []TableMatch `json:"tables"`
	Errors  []string     `json:"errors"`
}

// bestEntry is the entry pf matches addr with, the longest prefix that
// contains it; nil when that's a negated one, or there's none.
func bestEntry(entries []TableEntry, addr netip.Addr) *TableEntry {
	var best *TableEntry
	bits := -1
	for i := range entries {
		e := &entries[i]
		p, err := netip.ParsePrefix(e.Address)
		if err != nil {
			a, err := netip.ParseAddr(e.Address)
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Contains(addr) && p.Bits() > bits {
			best, bits = e, p.Bits()
		}
	}
	if best == nil || best.Negated {
		return nil
	}
	return best
}

// TableFind looks an address up in every table alias.
func (m *Manager) TableFind(address string) (*TableFind, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || addr.Zone() != "" {
		return nil, errorf(CodeInvalid, "%q isn't an address", address)
	}
	addr = addr.Unmap()
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}
	out := &TableFind{Address: addr.String(), Tables: []TableMatch{}, Errors: []string{}}
	for _, a := range model.Firewall.Aliases {
		if a.Type != pf.AliasTable && a.Type != pf.AliasURL {
			continue
		}
		entries, _, err := m.tableShow(a.Name, a.Type == pf.AliasTable)
		if err != nil {
			out.Errors = append(out.Errors, err.Error())
			continue
		}
		e := bestEntry(entries, addr)
		if e == nil {
			continue
		}
		match := TableMatch{Table: a.Name, Kind: "dynamic", Entry: e.Address, Added: e.Added, UsedBy: []TableRule{}}
		if a.Type == pf.AliasURL {
			match.Kind, match.Added = "list", nil
		}
		if a.ExpireMinutes != nil && match.Added != nil {
			t := match.Added.Add(time.Duration(*a.ExpireMinutes) * time.Minute)
			match.Expires = &t
		}
		for _, r := range model.Firewall.Rules {
			if ruleNamesTable(r, a.Name) {
				match.UsedBy = append(match.UsedBy, TableRule{ID: r.ID, Description: r.Description})
			}
		}
		out.Tables = append(out.Tables, match)
	}
	return out, nil
}

// ruleNamesTable says whether a rule uses a table: as its source or
// destination, its overload, or in a raw rule's text.
func ruleNamesTable(r pf.Rule, name string) bool {
	if r.IsRaw() {
		return strings.Contains(r.Text, "<"+name+">")
	}
	isIt := func(e pf.Endpoint) bool { return e.Type == pf.EndpointAlias && e.Alias == name }
	return isIt(r.Source) || isIt(r.Destination) || (r.State != nil && r.State.Overload == name)
}

// TableChangeRequest adds addresses to a dynamic table, takes them out,
// or empties it (Op "add", "delete", "flush").
type TableChangeRequest struct {
	Table     string   `json:"table"`
	Op        string   `json:"op"`
	Addresses []string `json:"addresses,omitempty"`
	// By is who asked, for the event log; the privileged side sets it
	// from the session, never from the request.
	By string `json:"-"`
}

// TableChange changes what a dynamic table holds now. A downloaded
// list's table is the list's: a change would last until its next
// download, so it's refused.
func (m *Manager) TableChange(req TableChangeRequest) error {
	_, a, err := m.tableAlias(req.Table)
	if err != nil {
		return err
	}
	if a.Type != pf.AliasTable {
		return errorf(CodeInvalid, "<%s> is a downloaded list: change the list, or add an address to a table of your own", a.Name)
	}
	var addrs []string
	switch req.Op {
	case "add", "delete":
		if len(req.Addresses) == 0 || len(req.Addresses) > tableChangeMax {
			return errorf(CodeInvalid, "name 1 to %d addresses", tableChangeMax)
		}
		for _, s := range req.Addresses {
			s = strings.TrimSpace(s)
			if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Zone() == "" {
				addrs = append(addrs, p.Masked().String())
			} else if ad, err := netip.ParseAddr(s); err == nil && ad.Zone() == "" {
				addrs = append(addrs, ad.Unmap().String())
			} else {
				return errorf(CodeInvalid, "%q isn't an address or network", s)
			}
		}
	case "flush":
	default:
		return errorf(CodeInvalid, "op is add, delete or flush, not %q", req.Op)
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	argv := append([]string{"pfctl", "-t", a.Name, "-T", req.Op}, addrs...)
	out, err := m.actions().Run(ctx, argv...)
	if err != nil {
		return errorf(CodeInternal, "pfctl -t %s -T %s: %s", a.Name, req.Op, strings.TrimSpace(string(out)))
	}
	who := req.By
	if who == "" {
		who = "Someone"
	}
	var msg string
	switch req.Op {
	case "add":
		msg = fmt.Sprintf("%s added %s to <%s>", who, strings.Join(addrs, ", "), a.Name)
	case "delete":
		msg = fmt.Sprintf("%s took %s out of <%s>", who, strings.Join(addrs, ", "), a.Name)
	case "flush":
		msg = fmt.Sprintf("%s emptied <%s>", who, a.Name)
	}
	log.Print(msg)
	m.RecordEvent(Event{Time: time.Now(), Kind: EventTable, Subject: a.Name, Message: msg})
	return nil
}
