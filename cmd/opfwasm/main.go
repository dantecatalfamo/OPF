//go:build js && wasm

// Command opfwasm is OPF's generators, validation and pf parser compiled
// to WebAssembly. The UI's offline preview build, which has no server to
// ask, calls these instead of the web process's /api/pf endpoints (its
// stand-in API, ui/src/lib/localApi.ts), so the preview shows exactly
// what the appliance would. The real UI calls them for previews once
// its model is large (ui/src/lib/generated.ts), rather than sending the
// whole model to the firewall on every edit.
//
// Each function takes a JSON string and returns one: {"ok": …} or
// {"error": "…"}.
package main

import (
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

type modelRequest struct {
	Model *pf.Model `json:"model"`
}

func (r modelRequest) model() *pf.Model {
	if r.Model == nil {
		return &pf.Model{}
	}
	return r.Model
}

// handle wraps a function of a JSON request as a JavaScript function of
// a JSON string.
func handle[Req any](f func(Req) (any, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		var req Req
		var out any
		var err error
		if len(args) != 1 || args[0].Type() != js.TypeString {
			err = errors.New("expected one JSON string")
		} else if err = json.Unmarshal([]byte(args[0].String()), &req); err == nil {
			out, err = pf.Safe(func() any {
				v, e := f(req)
				if e != nil {
					return e
				}
				return v
			})
			if e, ok := out.(error); ok && err == nil {
				out, err = nil, e
			}
		}
		var resp []byte
		if err != nil {
			resp, _ = json.Marshal(map[string]string{"error": err.Error()})
		} else {
			resp, _ = json.Marshal(map[string]any{"ok": out})
		}
		return string(resp)
	})
}

type renderRequest struct {
	Model   *pf.Model       `json:"model"`
	Rule    *pf.Rule        `json:"rule"`
	NAT     *pf.NATRule     `json:"nat"`
	Forward *pf.PortForward `json:"forward"`
}

type parseRequest struct {
	Text  string    `json:"text"`
	Model *pf.Model `json:"model"`
}

func main() {
	api := map[string]any{
		"ruleset": handle(func(r modelRequest) (any, error) { return pf.GeneratePfRuleset(r.model()), nil }),
		"derived": handle(func(r modelRequest) (any, error) { return pf.Derive(r.model()), nil }),
		"files":   handle(func(r modelRequest) (any, error) { return pf.GenerateFiles(r.model()), nil }),
		"validate": handle(func(r modelRequest) (any, error) {
			errs := pf.Validate(r.model())
			if errs == nil {
				errs = []pf.FieldError{}
			}
			return errs, nil
		}),
		"render": handle(func(r renderRequest) (any, error) {
			m := modelRequest{r.Model}.model()
			return pf.Render(m, r.Rule, r.NAT, r.Forward)
		}),
		"parse": handle(func(r parseRequest) (any, error) { return pf.ParseRule(r.Text, r.Model) }),
	}
	js.Global().Set("opfGenerators", js.ValueOf(api))
	select {} // keep the functions alive
}
