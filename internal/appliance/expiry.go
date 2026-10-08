package appliance

import (
	"context"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Tables whose addresses expire (pf.Alias.ExpireMinutes): pf never takes
// an address out of a table by itself, so one a rule's overload put
// there would stay until the table is flushed or pf restarts. Once a
// minute the collector has pf take out each address added longer ago
// than its table keeps them (pfctl -T expire: those whose statistics
// were last cleared then, which for an address a rule added is when it
// was added).

const expireEvery = time.Minute

var expiredRE = regexp.MustCompile(`(\d+)/\d+ addresses? expired`)

func (m *Manager) expireTables(model *pf.Model, now time.Time) {
	if model == nil || now.Sub(m.tablesExpired) < expireEvery {
		return
	}
	m.tablesExpired = now
	for _, a := range model.Firewall.Aliases {
		if a.Type != pf.AliasTable || a.ExpireMinutes == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := m.actions().Run(ctx, "pfctl", "-t", a.Name, "-T", "expire", strconv.Itoa(*a.ExpireMinutes*60))
		cancel()
		if err != nil {
			log.Printf("couldn't expire table <%s>'s old addresses: %v", a.Name, err)
			continue
		}
		if mm := expiredRE.FindSubmatch(out); mm != nil && string(mm[1]) != "0" {
			log.Printf("took %s address(es) out of table <%s>, added over %d minutes ago", mm[1], a.Name, *a.ExpireMinutes)
		}
	}
}
