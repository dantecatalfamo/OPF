package appliance

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/run"
)

// Downloads (the lists of pf URL aliases and DNS blocklists) are the
// only times OPF talks to the internet on its own, so they run ftp(1)
// as an unprivileged user (Fetcher), and this process only reads the
// lines it prints, capped in size. Parsing them is the list's own
// business.

// Limits on a download.
const (
	maxListBytes = 32 << 20
	fetchTimeout = 2 * time.Minute
)

// fetcher runs downloads: Fetcher, or else the Manager's runner.
func (m *Manager) fetcher() run.Runner {
	if m.Fetcher != nil {
		return m.Fetcher
	}
	return m.runner()
}

// fetchLines downloads a URL and returns its lines.
func (m *Manager) fetchLines(ctx context.Context, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	var lines []string
	size := 0
	tooBig := false
	line := func(l string) {
		if tooBig {
			return
		}
		if size += len(l) + 1; size > maxListBytes {
			tooBig = true
			cancel()
			return
		}
		lines = append(lines, l)
	}
	// -V: no progress meter. The URL comes from a validated model
	// (https:// only), and "--" ends the options before it.
	argv := []string{"ftp", "-V", "-o", "-", "--", url}
	var err error
	if s, ok := m.fetcher().(run.Streamer); ok {
		err = s.Stream(ctx, line, argv...)
	} else {
		var out []byte
		out, err = m.fetcher().Run(ctx, argv...)
		for _, l := range strings.Split(string(out), "\n") {
			line(l)
		}
	}
	if tooBig {
		return nil, fmt.Errorf("the list is bigger than %d MB", maxListBytes>>20)
	}
	if err != nil {
		// ftp's error is its last line of output ("ftp: Error retrieving
		// ...: 404 Not Found").
		msg := ""
		for i := len(lines) - 1; i >= 0 && msg == ""; i-- {
			msg = strings.TrimSpace(lines[i])
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(printable(msg, maxMessageRunes))
	}
	return lines, nil
}

// downloadedFrom reads the URL a saved list says it came from (its
// first line, "# Downloaded by OPF from <url> at <time>"), or "" if the
// file isn't there or doesn't say.
func downloadedFrom(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	rest, ok := strings.CutPrefix(line, "# Downloaded by OPF from ")
	if !ok {
		return ""
	}
	url, _, _ := strings.Cut(rest, " at ")
	return url
}

// emptyListError says why a download had nothing usable in it.
func emptyListError(skipped int, one, many string) error {
	if skipped == 0 {
		return errors.New("it's empty")
	}
	what := "lines that aren't " + many
	if skipped == 1 {
		what = "line that isn't " + one
	}
	return fmt.Errorf("it has no %s in it, just %d %s; is it the right URL?", many, skipped, what)
}
