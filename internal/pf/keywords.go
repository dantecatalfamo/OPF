package pf

import (
	"maps"
	"slices"
)

//go:generate go run ./genkeywords -o keywords_gen.go ${OPF_SRC}/sbin/pfctl/parse.y

// Keywords are the words pfctl reserves, sorted: for the conformance
// suite to compare with the release's parse.y.
func Keywords() []string { return slices.Sorted(maps.Keys(pfKeywords)) }
