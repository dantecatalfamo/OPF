package appliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

func TestWebhookFormats(t *testing.T) {
	// What a device on the network could call itself.
	e := Event{Time: time.Now(), Kind: EventDevice, Message: "New device at 192.168.1.9 on LAN (calls itself “<!channel> @everyone *bold* <@123> & x\r\nX-Evil: 1”)"}
	warn := Event{Time: time.Now(), Kind: EventGateway, Warning: true, Message: "Gateway WAN stopped answering"}

	f := formatDelivery(pf.WebhookSlack, "gw.office.arpa", e, false)
	var slack struct{ Text string }
	json.Unmarshal(f.body, &slack)
	if strings.Contains(slack.Text, "<!channel>") || strings.Contains(slack.Text, "<@") || !strings.Contains(slack.Text, "&lt;!channel&gt;") || !strings.Contains(slack.Text, "&amp; x") || !strings.HasPrefix(slack.Text, "*gw.office.arpa*") {
		t.Errorf("slack: %q", slack.Text)
	}

	f = formatDelivery(pf.WebhookDiscord, "gw.office.arpa", e, false)
	var discord struct {
		Content         string
		AllowedMentions struct{ Parse []string } `json:"allowed_mentions"`
	}
	json.Unmarshal(f.body, &discord)
	if discord.AllowedMentions.Parse == nil || len(discord.AllowedMentions.Parse) != 0 || !strings.Contains(discord.Content, `\*bold\*`) || !strings.HasPrefix(discord.Content, "**gw.office.arpa**") {
		t.Errorf("discord: %+v", discord)
	}

	f = formatDelivery(pf.WebhookNtfy, "gw.office.arpa", warn, false)
	if string(f.body) != warn.Message || f.headers["Priority"] != "4" || f.headers["Tags"] != "warning" || f.headers["Title"] != "gw.office.arpa: gateway" || !strings.HasPrefix(f.contentType, "text/plain") {
		t.Errorf("ntfy: %q %v %q", f.body, f.headers, f.contentType)
	}
	if f := formatDelivery(pf.WebhookNtfy, "gw", e, true); f.headers["Priority"] != "3" || f.headers["Title"] != "gw: test" {
		t.Errorf("ntfy test: %v", f.headers)
	}
	// A title can't carry a line break into the headers.
	if f := formatDelivery(pf.WebhookNtfy, "gw\r\nX-Evil: 1", e, false); strings.ContainsAny(f.headers["Title"], "\r\n") {
		t.Errorf("ntfy title: %q", f.headers["Title"])
	}

	f = formatDelivery(pf.WebhookJSON, "gw", e, true)
	var plain struct {
		Source string
		Test   bool
		Event  Event
	}
	if json.Unmarshal(f.body, &plain) != nil || plain.Source != "opf" || !plain.Test || plain.Event.Message != e.Message || f.contentType != "" {
		t.Errorf("json: %s", f.body)
	}
}
