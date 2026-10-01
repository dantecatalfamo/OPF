package appliance

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The system's own logs, as syslogd writes them, and the kernel's
// message buffer. Read as root, the last logLines of a file, filtered
// here so only what's asked for crosses to the web process. Log lines
// hold text others chose (a user name tried at login, a device's name
// from DHCP), so each is cleaned before it's sent.

// SystemLogs are the logs that can be read, by name: a file syslogd
// writes, or "dmesg" for the kernel's messages.
var SystemLogs = map[string]string{
	"messages": "/var/log/messages",
	"daemon":   "/var/log/daemon",
	"authlog":  "/var/log/authlog",
	"maillog":  "/var/log/maillog",
	"dmesg":    "",
}

const (
	logLines        = 5000 // read from the end of a log
	MaxLogPage      = 1000
	LogPage         = 300
	maxLogLineRunes = 2000
)

// SystemLogRequest asks for a log's lines, newest first: those from
// Program (all if empty) containing Query, at most Limit (LogPage if
// 0).
type SystemLogRequest struct {
	Log     string `json:"log"`
	Query   string `json:"query,omitempty"`
	Program string `json:"program,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// LogLine is a line of a log. The kernel's have no time or program.
type LogLine struct {
	Time    *time.Time `json:"time,omitempty"`
	Host    string     `json:"host,omitempty"`
	Program string     `json:"program,omitempty"`
	PID     int        `json:"pid,omitempty"`
	Message string     `json:"message"`
}

// SystemLog is a page of a log: the matching lines, newest first, how
// many were read from the end of the log, and the programs in them.
type SystemLog struct {
	Log      string    `json:"log"`
	Lines    []LogLine `json:"lines"`
	Matched  int       `json:"matched"`
	Read     int       `json:"read"`
	Programs []string  `json:"programs"`
	Error    string    `json:"error,omitempty"`
}

// logText is a log line fit to send: tabs as spaces (dmesg indents
// with them), then cleaned of control characters and capped.
func logText(s string) string {
	return printable(strings.ReplaceAll(s, "\t", "    "), maxLogLineRunes)
}

// SystemLog reads a log's last lines.
func (m *Manager) SystemLog(req SystemLogRequest) (*SystemLog, error) {
	path, ok := SystemLogs[req.Log]
	if !ok {
		return nil, errorf(CodeNotFound, "no log %q", printable(req.Log, 40))
	}
	req.Query = strings.TrimSpace(req.Query)
	switch {
	case len(req.Query) > 100:
		return nil, errorf(CodeInvalid, "the search is at most 100 characters")
	case len(req.Program) > 64:
		return nil, errorf(CodeInvalid, "a program's name is at most 64 characters")
	case req.Limit < 0 || req.Limit > MaxLogPage:
		return nil, errorf(CodeInvalid, "limit: 1 to %d", MaxLogPage)
	}
	if req.Limit == 0 {
		req.Limit = LogPage
	}
	res := &SystemLog{Log: req.Log, Lines: []LogLine{}, Programs: []string{}}
	var all []LogLine
	if path == "" {
		out, err := m.read("dmesg")
		if err != nil && out == "" {
			res.Error = "couldn't read the kernel's messages (dmesg)"
			return res, nil
		}
		ls := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(ls) > logLines {
			ls = ls[len(ls)-logLines:]
		}
		for _, l := range ls {
			if strings.TrimSpace(l) != "" {
				all = append(all, LogLine{Message: logText(l)})
			}
		}
	} else {
		out, err := m.read("tail", "-n", strconv.Itoa(logLines), path)
		if err != nil {
			res.Error = "couldn't read " + path
			return res, nil
		}
		for _, s := range sysinfo.ParseSyslog(out, time.Now()) {
			t := s.Time
			all = append(all, LogLine{Time: &t, Host: printable(s.Host, 255), Program: printable(s.Program, 64), PID: s.PID, Message: logText(s.Message)})
		}
	}
	res.Read = len(all)
	programs := map[string]bool{}
	q := strings.ToLower(req.Query)
	for i := len(all) - 1; i >= 0; i-- {
		l := all[i]
		if l.Program != "" {
			programs[l.Program] = true
		}
		if req.Program != "" && l.Program != req.Program {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(l.Program+" "+l.Message), q) {
			continue
		}
		res.Matched++
		if len(res.Lines) < req.Limit {
			res.Lines = append(res.Lines, l)
		}
	}
	for p := range programs {
		res.Programs = append(res.Programs, p)
	}
	sort.Strings(res.Programs)
	return res, nil
}
