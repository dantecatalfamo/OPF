package main

import (
	"slices"
	"testing"
)

func TestWithoutReadOnly(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{[]string{"-readonly", "-listen", "0.0.0.0:443"}, []string{"-listen", "0.0.0.0:443"}},
		{[]string{"--readonly", "-tls=off"}, []string{"-tls=off"}},
		{[]string{"-readonly=true", "-readonly=1"}, nil},
		{[]string{"-readonly=false", "-dry"}, []string{"-readonly=false", "-dry"}},
		{[]string{"-state", "/var/opf-readonly"}, []string{"-state", "/var/opf-readonly"}},
		{[]string{"readonly"}, []string{"readonly"}},
	} {
		if got := withoutReadOnly(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}
