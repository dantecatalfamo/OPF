package pf

import (
	"encoding/json"
	"strings"
	"testing"
)

// The empty model has no null lists. It isn't a valid configuration
// (no host name, no policies): it's never committed, only read.
func TestEmptyModel(t *testing.T) {
	m := EmptyModel()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "[null") || strings.Contains(string(data), ":null") {
		t.Errorf("a null in %s", data)
	}
}
