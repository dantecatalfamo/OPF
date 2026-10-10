package conformance

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The scan reads OPF's source for every command line it can run and
// fails on one the registry doesn't declare. It recognises command lines
// in these forms:
//
//   - a call to a function that takes a command line as its variadic
//     argument (runner.Run, m.read, …: argvAt), or runs a fixed command
//     with arguments added (prefixed), whose first word is a literal or a
//     variable set from literals in the same function;
//   - a []string literal whose first word is a base program, such as a
//     file's Check or Apply in config's registry. One that's appended to
//     is the start of a longer command line, and ends in "...";
//   - a []string{"prog"} that the same function then appends words to
//     (the diagnostics tools), whose literal words must be the Tool's.
//
// A word that is a string constant counts as its value; any other
// expression is a value OPF chooses ("*").

// argvAt gives, for each function that takes a command line as its
// variadic argument, the index of the argument where it starts.
var argvAt = map[string]int{
	"Run":            1, // run.Runner
	"Stream":         2, // run.Streamer
	"RunInput":       3, // run.Feeder
	"CommandContext": 1, // os/exec
	"Command":        0, // os/exec
	"read":           0, // appliance.Manager.read
	"logRun":         2, // config.Store.logRun
	"do":             1, // auth.System.do
}

// prefixed are functions that run a fixed command with arguments
// added: leases.Unbound's control and expectOK, and the DNS tools' ctl,
// run unbound-control.
var prefixed = map[string]struct {
	at     int
	prefix []string
}{
	"control":  {1, []string{"unbound-control", "-c", "/var/unbound/etc/unbound.conf"}},
	"expectOK": {1, []string{"unbound-control", "-c", "/var/unbound/etc/unbound.conf"}},
	"ctl":      {0, []string{"unbound-control", "-c", "/var/unbound/etc/unbound.conf"}},
}

// notCommands are functions with a variadic string argument that don't
// run anything.
var notCommands = map[string]bool{"oneOf": true, "checkKeyword": true, "expectKeyword": true}

type found struct {
	argv []string
	pos  string
}

type toolUse struct {
	program, word, pos string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// productionFiles are OPF's Go files, without tests, this package and
// the mock (which fakes the commands rather than running them).
func productionFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var files []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				if rel == filepath.Join("internal", "conformance") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			base := d.Name()
			if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") ||
				strings.HasPrefix(rel, filepath.Join("cmd", "opf", "mock")) {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// basePrograms are the programs in the base system's bin and sbin
// directories, as the suite listed them on each release.
func basePrograms(t *testing.T) map[string]bool {
	t.Helper()
	progs := map[string]bool{}
	lists, _ := filepath.Glob(filepath.Join("testdata", "openbsd-*", "programs.txt"))
	if len(lists) == 0 {
		t.Fatal("no testdata/openbsd-*/programs.txt")
	}
	for _, p := range lists {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			if w := strings.TrimSpace(s.Text()); w != "" {
				progs[w] = true
			}
		}
		f.Close()
	}
	return progs
}

type scan struct {
	fset     *token.FileSet
	root     string
	progs    map[string]bool
	consts   map[string]string // string constants by name; "" when two differ
	found    []found
	tools    []toolUse
	wrappers []string // functions with a variadic string argument nobody classified
	done     map[*ast.CompositeLit]bool
}

func (s *scan) pos(n ast.Node) string {
	p := s.fset.Position(n.Pos())
	rel, _ := filepath.Rel(s.root, p.Filename)
	return fmt.Sprintf("%s:%d", rel, p.Line)
}

func literal(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(b.Value)
	return v, err == nil
}

// value is a string literal's value, or a string constant's.
func (s *scan) value(e ast.Expr) (string, bool) {
	if v, ok := literal(e); ok {
		return v, true
	}
	var name string
	switch e := e.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return "", false
	}
	v, ok := s.consts[name]
	return v, ok && v != ""
}

// word is one word of a command line found in the source: its value,
// or "*".
func (s *scan) word(e ast.Expr) string {
	if v, ok := s.value(e); ok {
		return v
	}
	return "*"
}

// assigned are the literal strings a variable is set to in a function.
func assigned(body *ast.BlockStmt, name string) []string {
	var vals []string
	ast.Inspect(body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != len(a.Rhs) {
			return true
		}
		for i, l := range a.Lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name == name {
				if v, ok := literal(a.Rhs[i]); ok {
					vals = append(vals, v)
				}
			}
		}
		return true
	})
	return vals
}

func funcName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

func (s *scan) collectConsts(f *ast.File) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				v, ok := literal(vs.Values[i])
				if !ok {
					continue
				}
				if old, seen := s.consts[n.Name]; seen && old != v {
					s.consts[n.Name] = ""
				} else {
					s.consts[n.Name] = v
				}
			}
		}
	}
}

func (s *scan) file(f *ast.File) {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			s.wrapper(d)
			s.function(d.Body)
		case *ast.GenDecl:
			// Package-level []string literals (config's registry of files).
			ast.Inspect(d, func(n ast.Node) bool {
				if fl, ok := n.(*ast.FuncLit); ok {
					s.function(fl.Body)
					return false
				}
				if cl, ok := n.(*ast.CompositeLit); ok {
					s.slice(cl, false)
				}
				return true
			})
		}
	}
}

// wrapper notes a function taking a variadic string argument that
// isn't a known way of running a command.
func (s *scan) wrapper(fd *ast.FuncDecl) {
	ps := fd.Type.Params.List
	if len(ps) == 0 {
		return
	}
	el, ok := ps[len(ps)-1].Type.(*ast.Ellipsis)
	if !ok {
		return
	}
	if id, ok := el.Elt.(*ast.Ident); !ok || id.Name != "string" {
		return
	}
	n := fd.Name.Name
	if _, ok := argvAt[n]; ok {
		return
	}
	if _, ok := prefixed[n]; ok || notCommands[n] {
		return
	}
	s.wrappers = append(s.wrappers, fmt.Sprintf("%s (%s)", n, s.pos(fd)))
}

func singleProgram(s *scan, e ast.Expr) (string, bool) {
	cl, ok := e.(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 1 {
		return "", false
	}
	v, ok := literal(cl.Elts[0])
	return v, ok && s.progs[v]
}

func (s *scan) function(body *ast.BlockStmt) {
	// Variables built up with append from one program's name: the
	// diagnostics tools.
	built := map[string][]string{} // variable → programs
	ast.Inspect(body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, l := range a.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok || i >= len(a.Rhs) {
				continue
			}
			rhs := a.Rhs[i]
			if c, ok := rhs.(*ast.CallExpr); ok && funcName(c) == "append" && len(c.Args) > 0 {
				rhs = c.Args[0] // argv := append([]string{"nc"}, fam...)
			}
			if p, ok := singleProgram(s, rhs); ok {
				built[id.Name] = append(built[id.Name], p)
			}
		}
		return true
	})
	// Variables set to a longer []string literal and then appended to
	// hold the start of a command line.
	appended := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && funcName(c) == "append" && len(c.Args) > 0 {
			if id, ok := c.Args[0].(*ast.Ident); ok {
				appended[id.Name] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != len(a.Rhs) {
			return true
		}
		for i, l := range a.Lhs {
			if id, ok := l.(*ast.Ident); ok && appended[id.Name] {
				if cl, ok := a.Rhs[i].(*ast.CompositeLit); ok && len(cl.Elts) > 1 {
					s.slice(cl, true)
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if funcName(n) != "append" || len(n.Args) == 0 {
				s.call(body, n)
				return true
			}
			if id, ok := n.Args[0].(*ast.Ident); ok && built[id.Name] != nil {
				for _, a := range n.Args[1:] {
					if v, ok := s.value(a); ok {
						for _, p := range built[id.Name] {
							s.tools = append(s.tools, toolUse{p, v, s.pos(a)})
						}
					}
				}
			}
			// append([]string{"pfctl", "-t", name, "-T", op}, addrs...):
			// the start of a longer command line.
			if cl, ok := n.Args[0].(*ast.CompositeLit); ok && len(cl.Elts) > 1 {
				s.slice(cl, true)
			}
		case *ast.CompositeLit:
			if _, ok := singleProgram(s, n); ok {
				return true // a tool's start, checked through its appends
			}
			s.slice(n, false)
		}
		return true
	})
}

func (s *scan) call(body *ast.BlockStmt, call *ast.CallExpr) {
	name := funcName(call)
	at, ok := argvAt[name]
	var prefix []string
	if p, isPrefixed := prefixed[name]; isPrefixed {
		at, prefix, ok = p.at, p.prefix, true
	}
	if !ok || len(call.Args) <= at {
		return
	}
	var firsts []string
	rest := call.Args[at:]
	switch {
	case prefix != nil:
		firsts = []string{prefix[0]}
	case call.Ellipsis != token.NoPos && len(rest) == 1:
		return // the whole command line is built elsewhere: found as a slice there
	default:
		if v, ok := s.value(rest[0]); ok {
			firsts = []string{v}
		} else if id, ok := rest[0].(*ast.Ident); ok {
			firsts = assigned(body, id.Name)
		}
		rest = rest[1:]
	}
	for _, first := range firsts {
		argv := []string{first}
		if prefix != nil {
			argv = slices.Clone(prefix)
		}
		for i, a := range rest {
			if i == len(rest)-1 && call.Ellipsis != token.NoPos {
				argv = append(argv, "...")
				break
			}
			argv = append(argv, s.word(a))
		}
		s.found = append(s.found, found{argv, s.pos(call)})
	}
}

// slice records a []string literal that starts with a base program;
// more says it's the start of a longer command line.
func (s *scan) slice(cl *ast.CompositeLit, more bool) {
	if s.done[cl] {
		return
	}
	at, ok := cl.Type.(*ast.ArrayType)
	if !ok {
		return
	}
	if id, ok := at.Elt.(*ast.Ident); !ok || id.Name != "string" || len(cl.Elts) == 0 {
		return
	}
	first, ok := literal(cl.Elts[0])
	if !ok || !s.progs[first] {
		return
	}
	s.done[cl] = true
	argv := []string{first}
	for _, e := range cl.Elts[1:] {
		argv = append(argv, s.word(e))
	}
	if more {
		argv = append(argv, "...")
	}
	s.found = append(s.found, found{argv, s.pos(cl)})
}

func scanSource(t *testing.T) *scan {
	t.Helper()
	s := &scan{fset: token.NewFileSet(), root: repoRoot(t), progs: basePrograms(t),
		consts: map[string]string{}, done: map[*ast.CompositeLit]bool{}}
	var files []*ast.File
	for _, p := range productionFiles(t) {
		f, err := parser.ParseFile(s.fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		s.collectConsts(f)
	}
	for _, f := range files {
		s.file(f)
	}
	return s
}

// TestCommandsDeclared fails when OPF can run a command line, or pass a
// tool a word, that the registry doesn't declare. Declare it in
// registry.go, with the suite's test that checks it on OpenBSD.
func TestCommandsDeclared(t *testing.T) {
	inRepo(t)
	s := scanSource(t)
	if len(s.found) == 0 {
		t.Fatal("the scan found no commands at all")
	}
	var missing []string
	for _, f := range s.found {
		if slices.ContainsFunc(NotCommands, func(nc []string) bool { return slices.Equal(nc, f.argv) }) {
			continue
		}
		if !slices.ContainsFunc(Commands, func(c Command) bool { return c.Matches(f.argv) }) {
			missing = append(missing, fmt.Sprintf("%-44s %s", f.pos, strings.Join(f.argv, " ")))
		}
	}
	for _, u := range s.tools {
		if !slices.ContainsFunc(Tools, func(tl Tool) bool { return tl.Program == u.program && slices.Contains(tl.Words, u.word) }) {
			missing = append(missing, fmt.Sprintf("%-44s %s … %q", u.pos, u.program, u.word))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d command lines OPF runs aren't declared in internal/conformance's registry:\n%s", len(missing), strings.Join(missing, "\n"))
	}
	for _, w := range s.wrappers {
		t.Errorf("%s takes a list of strings: if it runs a command, add it to argvAt or prefixed in scan_test.go; if not, to notCommands", w)
	}
}

// TestDeclarationsChecked fails when a declaration names a suite test
// that doesn't exist, or a command OPF parses has no Format: each must
// be checked on OpenBSD.
func TestDeclarationsChecked(t *testing.T) {
	inRepo(t)
	files, _ := filepath.Glob("*_openbsd_test.go")
	tests := map[string]bool{}
	fset := token.NewFileSet()
	for _, p := range files {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && strings.HasPrefix(fd.Name.Name, "Test") {
				tests[fd.Name.Name] = true
			}
		}
	}
	for _, c := range Commands {
		if !tests[c.Test] {
			t.Errorf("%s: no suite test %s", strings.Join(c.Argv, " "), c.Test)
		}
		if tmpl := strings.Join(c.Argv, " "); c.Kind == Read && Formats[tmpl].Command == "" && !strings.HasPrefix(tmpl, "rcctl check") && tmpl != "encrypt" {
			t.Errorf("%s: OPF reads its output, but no Format declares it", tmpl)
		}
	}
	for _, tl := range Tools {
		if !tests[tl.Test] {
			t.Errorf("%s: no suite test %s", tl.Program, tl.Test)
		}
	}
}
