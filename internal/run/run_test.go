package run

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStream(t *testing.T) {
	var got []string
	err := Exec{}.Stream(context.Background(), func(l string) { got = append(got, l) }, "sh", "-c", "echo one; echo two >&2; printf 'three'")
	if err != nil || strings.Join(got, "|") != "one|two|three" {
		t.Errorf("got %q, %v", got, err)
	}
	// Overlong lines are cut, and the next line still arrives.
	got = nil
	Exec{}.Stream(context.Background(), func(l string) { got = append(got, l) }, "sh", "-c", "head -c 10000 /dev/zero | tr '\\0' x; echo; echo after")
	if len(got) != 2 || len(got[0]) != maxLine || got[1] != "after" {
		t.Errorf("long line: %d lines, first %d bytes", len(got), len(got[0]))
	}
	if err := (Exec{}).Stream(context.Background(), func(string) {}, "sh", "-c", "exit 3"); err == nil {
		t.Error("a failing command should return its error")
	}
	// Cancelling ends it.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	Exec{}.Stream(ctx, func(string) {}, "sleep", "10")
	if time.Since(start) > 5*time.Second {
		t.Error("cancel didn't stop the command")
	}
}
