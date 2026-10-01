package sysinfo

import (
	"strconv"
	"strings"
	"time"
)

// SyslogLine is one line of a file syslogd writes: "Sep 30 14:39:40 gw
// sshd[123]: message". Program is empty for syslogd's own "last message
// repeated" lines.
type SyslogLine struct {
	Time    time.Time `json:"time"`
	Host    string    `json:"host"`
	Program string    `json:"program,omitempty"`
	PID     int       `json:"pid,omitempty"`
	Message string    `json:"message"`
}

// ParseSyslog reads syslogd's lines, oldest first, as they are in the
// file. The timestamp has no year: each is taken to be the latest one
// that isn't after now. A line that isn't one (a continuation, a
// damaged line) is left out.
func ParseSyslog(out string, now time.Time) []SyslogLine {
	var ls []SyslogLine
	for _, l := range lines(out) {
		if s, ok := parseSyslogLine(l, now); ok {
			ls = append(ls, s)
		}
	}
	return ls
}

func parseSyslogLine(l string, now time.Time) (SyslogLine, bool) {
	var s SyslogLine
	if len(l) < 16 || l[15] != ' ' {
		return s, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", l[:15], now.Location())
	if err != nil {
		return s, false
	}
	s.Time = withYear(t, now)
	host, rest, ok := strings.Cut(l[16:], " ")
	if !ok || host == "" {
		return s, false
	}
	s.Host = host
	// "prog[pid]: msg", "prog: msg", "/bsd: msg"; or syslogd's own
	// "last message repeated 3 times", with no program.
	tag, msg, ok := strings.Cut(rest, ": ")
	if !ok || strings.ContainsAny(tag, " \t") || tag == "" {
		s.Message = rest
		return s, true
	}
	if i := strings.IndexByte(tag, '['); i > 0 && strings.HasSuffix(tag, "]") {
		pid, err := strconv.Atoi(tag[i+1 : len(tag)-1])
		if err != nil || pid < 0 {
			s.Message = rest
			return s, true
		}
		s.PID, tag = pid, tag[:i]
	}
	s.Program, s.Message = tag, msg
	return s, true
}
