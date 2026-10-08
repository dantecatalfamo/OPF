package appliance

import "testing"

func TestStateKind(t *testing.T) {
	for state, want := range map[string]string{
		"ESTABLISHED:ESTABLISHED": "open",
		"ESTABLISHED:FIN_WAIT_2":  "closing",
		"CLOSE_WAIT:LAST_ACK":     "closing",
		"TIME_WAIT:TIME_WAIT":     "closing",
		"SYN_SENT:CLOSED":         "closing", // a refused connection, on its way out
		"SYN_SENT:LISTEN":         "opening",
		"MULTIPLE:MULTIPLE":       "active",
		"SINGLE:MULTIPLE":         "active",
		"SINGLE:NO_TRAFFIC":       "one-way",
		"NO_TRAFFIC:NO_TRAFFIC":   "waiting",
		"0:0":                     "other",
	} {
		if got := StateKind(state); got != want {
			t.Errorf("%s: %s, want %s", state, got, want)
		}
	}
}
