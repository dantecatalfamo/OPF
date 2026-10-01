package appliance

import (
	"strings"
	"testing"
)

func TestSystemLog(t *testing.T) {
	c := &captured{dir: "handwritten", files: map[string]string{"tail -n 5000 /var/log/messages": "syslog_messages.txt", "dmesg": "syslog_messages.txt"}}
	m := &Manager{Runner: c}
	l, err := m.SystemLog(SystemLogRequest{Log: "messages"})
	if err != nil || l.Error != "" || l.Read != 10 || len(l.Lines) != 10 || l.Matched != 10 {
		t.Fatalf("%+v %v", l, err)
	}
	// Newest first, as the file has them: the last line of the file
	// (the one with an odd pid) comes first.
	if !strings.Contains(l.Lines[0].Message, "odd pid") || l.Lines[len(l.Lines)-1].Program != "syslogd" {
		t.Errorf("order: first %+v, last %+v", l.Lines[0], l.Lines[len(l.Lines)-1])
	}
	if strings.Join(l.Programs, ",") != "/bsd,dhcpd,doas,ntpd,sshd,syslogd,unbound" {
		t.Errorf("programs %v", l.Programs)
	}
	if l, _ := m.SystemLog(SystemLogRequest{Log: "messages", Program: "sshd"}); l.Matched != 2 {
		t.Errorf("sshd: %d", l.Matched)
	}
	if l, _ := m.SystemLog(SystemLogRequest{Log: "messages", Query: "ACCEPTED"}); l.Matched != 1 || l.Lines[0].PID != 88213 {
		t.Errorf("search: %+v", l.Lines)
	}
	if l, _ := m.SystemLog(SystemLogRequest{Log: "messages", Limit: 3}); len(l.Lines) != 3 || l.Matched != 10 {
		t.Errorf("limit: %d of %d", len(l.Lines), l.Matched)
	}
	// dmesg's lines are the kernel's, as they are, without times.
	if l, _ := m.SystemLog(SystemLogRequest{Log: "dmesg"}); l.Read != 12 || l.Lines[0].Time != nil || l.Lines[0].Message != "    continuation of something" {
		t.Errorf("dmesg: %d %+v", l.Read, l.Lines[0])
	}
	for _, bad := range []SystemLogRequest{{Log: "../../etc/master.passwd"}, {Log: "messages", Limit: MaxLogPage + 1}, {Log: "messages", Query: strings.Repeat("x", 101)}} {
		if _, err := m.SystemLog(bad); err == nil {
			t.Errorf("took %+v", bad)
		}
	}
	// A log that can't be read says so.
	if l, _ := m.SystemLog(SystemLogRequest{Log: "maillog"}); l.Error == "" {
		t.Error("no error for an unreadable log")
	}
}
