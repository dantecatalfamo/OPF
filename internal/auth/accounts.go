package auth

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// account is a user's line in master.passwd. Only what's needed is
// kept: the password hash itself never leaves this file's reading, as
// a fingerprint to notice it changing.
type account struct {
	Name   string
	GID    int
	Class  string
	Expire int64    // seconds since 1970; 0 never
	Pass   [32]byte // SHA-256 of the hash field
}

func (a *account) expired(now time.Time) bool {
	return a.Expire != 0 && now.Unix() >= a.Expire
}

// lookupUser finds a user in master.passwd (name:password:uid:gid:
// class:change:expire:gecos:home:shell); nil if there's none.
func lookupUser(path, name string) (*account, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), ":")
		if len(fs) != 10 || fs[0] != name {
			continue
		}
		gid, err := strconv.Atoi(fs[3])
		if err != nil {
			return nil, fmt.Errorf("%s: %s has group %q", path, name, fs[3])
		}
		exp, _ := strconv.ParseInt(fs[6], 10, 64)
		return &account{
			Name: name, GID: gid, Class: fs[4], Expire: exp,
			Pass: sha256.Sum256([]byte(fs[1])),
		}, nil
	}
	return nil, sc.Err()
}

// groupMembers is which of the groups in names /etc/group lists user
// in. Only being listed counts, not a primary group whose id matches:
// a group made later can be given an id an account was left with when
// its own group was deleted, and that mustn't make the account an
// admin (seen on openbsd-dev).
func groupMembers(path string, names []string, user string, _ int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var in []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), ":")
		if len(fs) != 4 || !slices.Contains(names, fs[0]) {
			continue
		}
		if slices.Contains(strings.Split(fs[3], ","), user) {
			in = append(in, fs[0])
		}
	}
	return in, sc.Err()
}

// loginStyle is the first login style the class's auth-opf, or else
// auth, capability lists in login.conf; "" when neither does.
func loginStyle(path, class string) (string, error) {
	db, err := readCapDB(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	rec := db.find(class)
	if rec == nil {
		rec = db.find("default")
	}
	for _, c := range []string{"auth-opf", "auth"} {
		if v, ok := db.get(rec, c, 0); ok {
			return strings.TrimSpace(strings.Split(v, ",")[0]), nil
		}
	}
	return "", nil
}

// capDB is a getcap(3) database: records of "name|alias:cap=value:
// flag:cap@:tc=other:", lines joined by a backslash at their end, "#"
// starting a comment line.
type capDB [][]string // each record's fields; [0] holds the names

func readCapDB(path string) (capDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var db capDB
	var cur strings.Builder
	flush := func() {
		if r := strings.TrimSpace(cur.String()); r != "" {
			var fields []string
			for _, f := range strings.Split(r, ":") {
				if f = strings.TrimSpace(f); f != "" {
					fields = append(fields, f)
				}
			}
			db = append(db, fields)
		}
		cur.Reset()
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") && cur.Len() == 0 {
			continue
		}
		if l, cont := strings.CutSuffix(line, "\\"); cont {
			cur.WriteString(l)
			continue
		}
		cur.WriteString(line)
		flush()
	}
	flush()
	return db, nil
}

func (db capDB) find(name string) []string {
	for _, r := range db {
		if len(r) > 0 && slices.Contains(strings.Split(r[0], "|"), name) {
			return r
		}
	}
	return nil
}

// get is a string capability's value, following tc= in place; a
// capability cancelled with "name@" has none.
func (db capDB) get(rec []string, name string, depth int) (string, bool) {
	if rec == nil || depth > 32 {
		return "", false
	}
	for _, f := range rec[1:] {
		switch {
		case f == name+"@":
			return "", false
		case strings.HasPrefix(f, name+"="):
			return f[len(name)+1:], true
		case strings.HasPrefix(f, "tc="):
			if v, ok := db.get(db.find(f[3:]), name, depth+1); ok {
				return v, true
			}
		}
	}
	return "", false
}
