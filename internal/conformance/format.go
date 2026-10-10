package conformance

import (
	"fmt"
	"regexp"
	"strings"
)

// A Format is what OPF knows of a command's output: every kind of line
// it can print, by name and pattern. Check fails on a line that fits
// none of them, and on a line Need names that never appears, so an
// output that gains, loses or reshapes a line fails even when OPF's
// parser would have skipped it without a word.
//
// Patterns are written from the program's source (the function that
// prints each line), not only from a sample, and spell out every name
// OPF knows (counters, keys, sections) rather than matching any word,
// so a new or renamed one fails too.
type Format struct {
	// Command is the registry's command line whose output this is.
	Command string
	// Fixture is the file name the suite saves the output under.
	Fixture string
	// Lines are the kinds of line the output may have.
	Lines []Line
	// Need names Lines that must each appear at least once.
	Need []string
	// Free says the output is free text OPF only shows, so any line
	// fits (dmesg); Check then only applies Need.
	Free bool
}

// A Line is one kind of line in an output.
type Line struct {
	Name string
	RE   *regexp.Regexp
}

// L makes a Line; the pattern is anchored at both ends.
func L(name, pattern string) Line {
	return Line{Name: name, RE: regexp.MustCompile("^(?:" + pattern + ")$")}
}

// words is a pattern matching exactly one of the names.
func words(names ...string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return "(?:" + strings.Join(q, "|") + ")"
}

// Check returns what doesn't fit: lines that fit no kind (the first
// few, with their numbers) and needed kinds that never appear.
func (f Format) Check(out string) []string {
	var problems []string
	seen := map[string]bool{}
	unknown := 0
	var lines []string // none for no output, not one empty line
	if out != "" {
		lines = strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	}
	for i, l := range lines {
		matched := false
		for _, k := range f.Lines {
			if k.RE.MatchString(l) {
				seen[k.Name] = true
				matched = true
				break
			}
		}
		if !matched && !f.Free {
			unknown++
			if unknown <= 10 {
				problems = append(problems, fmt.Sprintf("line %d fits no kind of line OPF knows: %q", i+1, l))
			}
		}
	}
	if unknown > 10 {
		problems = append(problems, fmt.Sprintf("and %d more lines that fit nothing", unknown-10))
	}
	for _, n := range f.Need {
		if !seen[n] {
			problems = append(problems, fmt.Sprintf("no %s line", n))
		}
	}
	return problems
}

// Formats lists the output format of every command OPF parses, by its
// registry command line.
var Formats = map[string]Format{}

func addFormats(fs ...Format) {
	for _, f := range fs {
		if _, dup := Formats[f.Command]; dup {
			panic("two formats for " + f.Command)
		}
		Formats[f.Command] = f
	}
}
