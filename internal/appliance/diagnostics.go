package appliance

import (
	"errors"

	"github.com/dantecatalfamo/OPF/internal/diag"
)

// The diagnostic tools (package diag) run here, in the privileged
// process, with the Manager's Runner.

func (m *Manager) runs() *diag.Runs {
	m.diagOnce.Do(func() { m.diag = &diag.Runs{Runner: m.runner()} })
	return m.diag
}

func diagError(err error) error {
	var inv *diag.Invalid
	switch {
	case err == nil:
		return nil
	case errors.As(err, &inv):
		return &Error{Code: CodeInvalid, Message: inv.Message, Details: []Detail{{Path: inv.Field, Message: inv.Message}}}
	case errors.Is(err, diag.ErrBusy):
		return errorf(CodeBusy, "%s", err)
	case errors.Is(err, diag.ErrNotFound):
		return errorf(CodeNotFound, "%s", err)
	}
	return apiError(err)
}

// StartTool starts a diagnostic tool.
func (m *Manager) StartTool(req diag.Request) (*diag.Run, error) {
	r, err := m.runs().Start(req)
	return r, diagError(err)
}

// ToolRun returns a tool's run and its output from line from on.
func (m *Manager) ToolRun(id string, from int) (*diag.Run, error) {
	r, err := m.runs().Get(id, from)
	return r, diagError(err)
}

// CancelTool stops a tool's run.
func (m *Manager) CancelTool(id string) error {
	return diagError(m.runs().Cancel(id))
}
