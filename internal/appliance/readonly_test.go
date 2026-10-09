package appliance

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

// Every API method is either refused or allowed in read-only mode, and
// ReadOnlyAPI does what the lists say: a refused method answers
// read_only without reaching the API inside, and an allowed one reaches
// it. A new method that's in neither list fails here, so none is
// allowed by default.
func TestReadOnlyAPIClassifiesEveryMethod(t *testing.T) {
	api := reflect.TypeFor[API]()
	for i := range api.NumMethod() {
		name := api.Method(i).Name
		refused, allowed := slices.Contains(readOnlyRefused, name), slices.Contains(readOnlyAllowed, name)
		if refused == allowed {
			t.Errorf("%s: in read-only mode, is it refused or allowed? (readOnlyRefused, readOnlyAllowed)", name)
			continue
		}
		reached, err := callZero(t, ReadOnlyAPI(nil), name)
		switch {
		case refused && reached:
			t.Errorf("%s is refused but reached the API", name)
		case refused && !isReadOnly(err):
			t.Errorf("%s is refused but answered %v", name, err)
		case allowed && !reached:
			t.Errorf("%s is allowed but didn't reach the API: %v", name, err)
		}
	}
	for _, n := range append(slices.Clone(readOnlyRefused), readOnlyAllowed...) {
		if _, ok := api.MethodByName(n); !ok {
			t.Errorf("%s is listed but isn't an API method", n)
		}
	}
}

// The parts of ServiceAction and DNSTool that only look go through.
func TestReadOnlyAPILetsLookingThrough(t *testing.T) {
	ro := ReadOnlyAPI(nil)
	for _, c := range []struct {
		name string
		call func() error
		pass bool
	}{
		{"check a service", func() error {
			_, err := ro.ServiceAction(ServiceActionRequest{Name: "sshd", Action: "check"})
			return err
		}, true},
		{"restart a service", func() error {
			_, err := ro.ServiceAction(ServiceActionRequest{Name: "sshd", Action: "restart"})
			return err
		}, false},
		{"look a name up", func() error { _, err := ro.DNSTool(DNSToolRequest{Tool: "lookup", Name: "example.com"}); return err }, true},
		{"flush a name", func() error { _, err := ro.DNSTool(DNSToolRequest{Tool: "flush", Name: "example.com"}); return err }, false},
		{"flush everything", func() error { _, err := ro.DNSTool(DNSToolRequest{Tool: "flush_negative"}); return err }, false},
	} {
		reached, err := reaches(c.call)
		if reached != c.pass || (!c.pass && !isReadOnly(err)) {
			t.Errorf("%s: reached %v, %v", c.name, reached, err)
		}
	}
}

// callZero calls api's method with zero arguments; reached says it got
// to the API inside (nil, so calling it panics).
func callZero(t *testing.T, api API, name string) (bool, error) {
	m := reflect.ValueOf(api).MethodByName(name)
	args := make([]reflect.Value, m.Type().NumIn())
	for i := range args {
		args[i] = reflect.Zero(m.Type().In(i))
	}
	return reaches(func() error {
		out := m.Call(args)
		if e, _ := out[len(out)-1].Interface().(error); e != nil {
			return e
		}
		return nil
	})
}

func reaches(f func() error) (reached bool, err error) {
	defer func() {
		if recover() != nil {
			reached = true
		}
	}()
	return false, f()
}

func isReadOnly(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == CodeReadOnly
}
