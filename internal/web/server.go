// Package web serves the management UI. Pages are rendered on the
// server with html/template; htmx swaps in fragments for actions that
// don't need a full page load.
package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
)

//go:embed templates static
var assets embed.FS

var pages = []string{"index.html", "file.html", "changes.html", "history.html", "entry.html", "error.html"}

type Server struct {
	store config.Manager
	tmpl  map[string]*template.Template
	mux   *http.ServeMux
}

func New(store config.Manager) (*Server, error) {
	s := &Server{store: store, tmpl: map[string]*template.Template{}, mux: http.NewServeMux()}
	funcs := template.FuncMap{"difflines": diffLines}
	for _, p := range pages {
		t, err := template.New(p).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/fragments.html", "templates/"+p)
		if err != nil {
			return nil, err
		}
		s.tmpl[p] = t
	}
	frag, err := template.New("fragments").Funcs(funcs).ParseFS(assets, "templates/fragments.html")
	if err != nil {
		return nil, err
	}
	s.tmpl["fragments"] = frag

	static, _ := fs.Sub(assets, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	s.mux.HandleFunc("GET /{$}", s.index)
	s.mux.HandleFunc("GET /files/{name}", s.editFile)
	s.mux.HandleFunc("POST /files/{name}", s.stageFile)
	s.mux.HandleFunc("POST /files/{name}/check", s.checkFile)
	s.mux.HandleFunc("POST /files/{name}/discard", s.discardFile)
	s.mux.HandleFunc("GET /changes", s.changes)
	s.mux.HandleFunc("POST /changes/discard", s.discardAll)
	s.mux.HandleFunc("POST /commit", s.commit)
	s.mux.HandleFunc("POST /confirm", s.confirm)
	s.mux.HandleFunc("POST /revert", s.revert)
	s.mux.HandleFunc("GET /banner", s.bannerFragment)
	s.mux.HandleFunc("GET /history", s.history)
	s.mux.HandleFunc("GET /history/{id}", s.entry)
	s.mux.HandleFunc("POST /history/{id}/stage", s.stageFromHistory)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// page is the data passed to every full-page template.
type page struct {
	Title  string
	Banner banner
	Data   any
}

type banner struct {
	Pending   *config.Entry
	Remaining int
	Staged    int
	Reverted  *config.Entry // recently reverted commit, so it doesn't go unnoticed
}

func (s *Server) banner() banner {
	var b banner
	if p := s.store.Pending(); p != nil {
		b.Pending = p
		b.Remaining = max(0, int(math.Ceil(time.Until(p.Deadline).Seconds())))
	}
	if changes, err := s.store.Changes(); err == nil {
		b.Staged = len(changes)
	}
	if h, err := s.store.History(); err == nil && len(h) > 0 {
		if last := h[0]; last.Status == config.StatusReverted && time.Since(last.Time) < 10*time.Minute {
			b.Reverted = last
		}
	}
	return b
}

func (s *Server) render(w http.ResponseWriter, name, title string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl[name].ExecuteTemplate(&buf, "layout", page{Title: title, Banner: s.banner(), Data: data}); err != nil {
		log.Printf("web: rendering %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) fragment(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl["fragments"].ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("web: rendering fragment %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// fail reports an error. htmx doesn't swap error responses by default,
// so for htmx requests the message is sent as a 200 fragment instead.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, config.ErrUnknownFile) {
		status = http.StatusNotFound
	}
	if r.Header.Get("HX-Request") == "true" {
		s.fragment(w, "error", err.Error())
		return
	}
	w.WriteHeader(status)
	s.render(w, "error.html", "Error", err.Error())
}

func (s *Server) lookup(name string) (config.File, error) {
	for _, f := range s.store.Files() {
		if f.Name == name {
			return f, nil
		}
	}
	return config.File{}, fmt.Errorf("%w: %s", config.ErrUnknownFile, name)
}

// changed tells the banner to refresh.
func changed(w http.ResponseWriter) { w.Header().Set("HX-Trigger", "opf-changed") }

type fileRow struct {
	File   config.File
	Staged bool
	Exists bool
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	var rows []fileRow
	for _, f := range s.store.Files() {
		_, staged, err := s.store.Staged(f.Name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_, exists, err := s.store.Live(f.Name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		rows = append(rows, fileRow{File: f, Staged: staged, Exists: exists})
	}
	s.render(w, "index.html", "Configuration", rows)
}

type fileData struct {
	File    config.File
	Content string
	Change  *config.Change
	Exists  bool
}

func (s *Server) fileData(f config.File) (fileData, error) {
	content, err := s.store.Current(f.Name)
	if err != nil {
		return fileData{}, err
	}
	_, exists, err := s.store.Live(f.Name)
	if err != nil {
		return fileData{}, err
	}
	d := fileData{File: f, Content: string(content), Exists: exists}
	changes, err := s.store.Changes()
	if err != nil {
		return fileData{}, err
	}
	for _, c := range changes {
		if c.File.Name == f.Name {
			d.Change = &c
		}
	}
	return d, nil
}

func (s *Server) editFile(w http.ResponseWriter, r *http.Request) {
	f, err := s.lookup(r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.fileData(f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, "file.html", f.Name, d)
}

func (s *Server) stageFile(w http.ResponseWriter, r *http.Request) {
	f, err := s.lookup(r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.Stage(f.Name, []byte(r.FormValue("content"))); err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.fileData(f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	changed(w)
	s.fragment(w, "stage-result", d)
}

type checkResult struct {
	OK     bool
	Output string
}

func (s *Server) checkFile(w http.ResponseWriter, r *http.Request) {
	f, err := s.lookup(r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, ok, err := s.store.CheckContent(r.Context(), f.Name, []byte(r.FormValue("content")))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.fragment(w, "check-result", checkResult{OK: ok, Output: out})
}

func (s *Server) discardFile(w http.ResponseWriter, r *http.Request) {
	f, err := s.lookup(r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.Discard(f.Name); err != nil {
		s.fail(w, r, err)
		return
	}
	next := "/files/" + f.Name
	if r.FormValue("next") == "changes" {
		next = "/changes"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) discardAll(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DiscardAll(); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	changes, err := s.store.Changes()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, "changes.html", "Staged changes", changes)
}

type commitResult struct {
	Entry *config.Entry
	Err   string
	Check *config.CheckError
	Drift *config.DriftError
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.Commit(r.Context())
	res := commitResult{Entry: e}
	if err != nil {
		res.Err = err.Error()
		errors.As(err, &res.Check)
		errors.As(err, &res.Drift)
	}
	changed(w)
	s.fragment(w, "commit-result", res)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Confirm(); err != nil {
		s.fail(w, r, err)
		return
	}
	changed(w)
	s.fragment(w, "banner", s.banner())
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Revert(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	changed(w)
	s.fragment(w, "banner", s.banner())
}

func (s *Server) bannerFragment(w http.ResponseWriter, r *http.Request) {
	s.fragment(w, "banner", s.banner())
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.History()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, "history.html", "History", h)
}

type entryFile struct {
	config.EntryFile
	Diff string
}

type entryData struct {
	Entry *config.Entry
	Files []entryFile
}

func (s *Server) entry(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.Entry(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := entryData{Entry: e}
	for _, ef := range e.Files {
		diff, err := s.store.EntryDiff(e.ID, ef.Name)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Files = append(d.Files, entryFile{EntryFile: ef, Diff: diff})
	}
	s.render(w, "entry.html", "Commit "+e.ID, d)
}

func (s *Server) stageFromHistory(w http.ResponseWriter, r *http.Request) {
	err := s.store.StageFromHistory(r.PathValue("id"), r.FormValue("file"), r.FormValue("version") == "old")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

type diffLine struct {
	Class string
	Text  string
}

func diffLines(diff string) []diffLine {
	var out []diffLine
	for line := range strings.Lines(diff) {
		line = strings.TrimSuffix(line, "\n")
		class := ""
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			class = "hdr"
		case strings.HasPrefix(line, "@@"):
			class = "hunk"
		case strings.HasPrefix(line, "+"):
			class = "add"
		case strings.HasPrefix(line, "-"):
			class = "del"
		}
		out = append(out, diffLine{Class: class, Text: line})
	}
	return out
}
