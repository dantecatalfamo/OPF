// Command genkeywords writes keywords_gen.go from pfctl's parse.y: the
// words pfctl reserves, which a macro (an interface id) can't be named.
// Run it on a new release's parse.y (the conformance suite's TestSource
// says when they differ):
//
//	go run ./internal/pf/genkeywords -o internal/pf/keywords_gen.go path/to/sbin/pfctl/parse.y
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"regexp"
	"sort"
)

var (
	revRE   = regexp.MustCompile(`\$OpenBSD: parse\.y,v ([0-9.]+) `)
	tableRE = regexp.MustCompile(`(?s)static const struct keywords keywords\[\] = \{(.*?)\n\s*\};`)
	entryRE = regexp.MustCompile(`\{\s*"([^"]+)",\s*[A-Z0-9_]+\s*\}`)
)

func main() {
	out := flag.String("o", "keywords_gen.go", "the file to write")
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: genkeywords [-o file] parse.y")
	}
	src, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	rev := revRE.FindSubmatch(src)
	table := tableRE.FindSubmatch(src)
	if rev == nil || table == nil {
		log.Fatalf("%s: no revision or keywords table", flag.Arg(0))
	}
	var words []string
	for _, m := range entryRE.FindAllSubmatch(table[1], -1) {
		words = append(words, string(m[1]))
	}
	sort.Strings(words)
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated from OpenBSD sbin/pfctl/parse.y %s (the keywords table); DO NOT EDIT.\n\n", rev[1])
	b.WriteString("package pf\n\n// pfKeywords are the words pfctl reserves. A macro can't be named after\n// one, since its definition then doesn't parse.\nvar pfKeywords = map[string]bool{\n")
	for _, w := range words {
		fmt.Fprintf(&b, "\t%q: true,\n", w)
	}
	b.WriteString("}\n")
	code, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, code, 0644); err != nil {
		log.Fatal(err)
	}
}
