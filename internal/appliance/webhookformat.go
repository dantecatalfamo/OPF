package appliance

import (
	"encoding/json"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// How an event is sent, by a webhook's format: OPF's own JSON, or a
// message as Slack, Discord or ntfy take one. Messages can quote what a
// device calls itself, which anyone on the network chooses, so each is
// made harmless for where it's going: no Slack mention or link, no
// Discord mention, no header that isn't one.

type formatted struct {
	body        []byte
	contentType string
	headers     map[string]string
}

func formatDelivery(format, host string, e Event, test bool) formatted {
	line := e.Message
	switch format {
	case pf.WebhookSlack:
		// Slack reads <...> as mentions and links, and & as their
		// escape; escaped, a device calling itself <!channel> pings no
		// one.
		esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace
		text := "*" + esc(host) + "* " + icon(e, ":warning:", ":information_source:") + " " + esc(line)
		b, _ := json.Marshal(map[string]any{"text": text, "unfurl_links": false, "unfurl_media": false})
		return formatted{body: b}
	case pf.WebhookDiscord:
		// allowed_mentions with nothing in parse: @everyone, @here and
		// <@...> stay text.
		text := "**" + discordEscape(host) + "** " + icon(e, "⚠️", "ℹ️") + " " + discordEscape(line)
		b, _ := json.Marshal(map[string]any{"content": text, "username": "OPF", "allowed_mentions": map[string]any{"parse": []string{}}})
		return formatted{body: b}
	case pf.WebhookNtfy:
		priority, tags := "3", "information_source"
		if e.Warning {
			priority, tags = "4", "warning"
		}
		title := host + ": " + eventTitle(e.Kind)
		if test {
			title = host + ": test"
		}
		return formatted{
			body:        []byte(line),
			contentType: "text/plain; charset=utf-8",
			headers:     map[string]string{"Title": headerSafe(title), "Priority": priority, "Tags": tags},
		}
	}
	b, _ := json.Marshal(struct {
		Source string `json:"source"`
		Host   string `json:"host"`
		Test   bool   `json:"test,omitempty"`
		Event  Event  `json:"event"`
	}{"opf", host, test, e})
	return formatted{body: b}
}

func icon(e Event, warn, info string) string {
	if e.Warning {
		return warn
	}
	return info
}

// discordEscape keeps Discord's markdown from reading a name as
// formatting: *, _, ~, `, | and > are escaped.
func discordEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\*_~`|>", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// headerSafe is s fit for a header value: printable, one line.
func headerSafe(s string) string {
	s = printable(s, 200)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func eventTitle(kind string) string {
	return map[string]string{
		EventOPF: "OPF", EventLink: "link", EventAddress: "address", EventGateway: "gateway", EventDevice: "new device",
		EventVPN: "VPN", EventService: "service", EventList: "list", EventUpdates: "security patches", EventCommit: "change",
	}[kind]
}
