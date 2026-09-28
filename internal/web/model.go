package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// ModelManager handles the appliance configuration model.
// It is the single source of truth for generating config files.
type ModelManager struct {
	mu       sync.RWMutex
	model    *pf.Model
	path     string // path to config.json
	modified bool   // true if model has unsaved changes
}

// NewModelManager creates a new model manager.
// If path exists, it loads the model from disk.
// Otherwise, it starts with an empty model.
func NewModelManager(path string) (*ModelManager, error) {
	m := &ModelManager{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Start with empty model
			m.model = &pf.Model{}
			return m, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var model pf.Model
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	m.model = &model
	return m, nil
}

// Get returns the current model.
func (m *ModelManager) Get() *pf.Model {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.model
}

// Set replaces the entire model.
func (m *ModelManager) Set(model *pf.Model) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.model = model
	m.modified = true
}

// Save persists the model to disk.
func (m *ModelManager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.MarshalIndent(m.model, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(m.path, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	m.modified = false
	return nil
}

// IsModified returns true if the model has unsaved changes.
func (m *ModelManager) IsModified() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.modified
}

// GenerateFiles generates all config files from the current model.
func (m *ModelManager) GenerateFiles() []pf.GeneratedFile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return pf.GenerateFiles(m.model)
}

// GeneratePfConf generates just pf.conf from the current model.
func (m *ModelManager) GeneratePfConf() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return pf.GeneratePfConf(m.model)
}

// PreviewFiles generates files from a proposed model without applying it.
func (m *ModelManager) PreviewFiles(proposed *pf.Model) []pf.GeneratedFile {
	return pf.GenerateFiles(proposed)
}

// ---------- HTTP API Handlers ----------

// apiGetModel returns the current model.
// GET /api/model
func (s *Server) apiGetModel(w http.ResponseWriter, r *http.Request) {
	if s.modelMgr == nil {
		apiError(w, "model manager not initialized", http.StatusInternalServerError)
		return
	}
	apiJSON(w, s.modelMgr.Get())
}

// apiPutModel replaces the entire model.
// PUT /api/model
func (s *Server) apiPutModel(w http.ResponseWriter, r *http.Request) {
	if s.modelMgr == nil {
		apiError(w, "model manager not initialized", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		apiError(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var model pf.Model
	if err := json.Unmarshal(body, &model); err != nil {
		apiError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.modelMgr.Set(&model)
	apiJSON(w, map[string]string{"status": "ok"})
}

// PreviewResponse contains the generated files for preview.
type PreviewResponse struct {
	Files []pf.GeneratedFile `json:"files"`
}

// apiPreviewModel generates files from a proposed model without applying.
// POST /api/model/preview
func (s *Server) apiPreviewModel(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apiError(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var model pf.Model
	if err := json.Unmarshal(body, &model); err != nil {
		apiError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	files := pf.GenerateFiles(&model)
	apiJSON(w, PreviewResponse{Files: files})
}

// ApplyRequest contains the model to apply.
type ApplyRequest struct {
	Model pf.Model `json:"model"`
}

// ApplyResponse contains the result of applying a model.
type ApplyResponse struct {
	Files   []pf.GeneratedFile `json:"files"`
	Staged  int                `json:"staged"`
	Error   string             `json:"error,omitempty"`
	Details []FileError        `json:"details,omitempty"`
}

// FileError describes an error with a specific file.
type FileError struct {
	Path   string `json:"path"`
	Error  string `json:"error"`
	Output string `json:"output,omitempty"`
}

// apiApplyModel generates files from the model, validates them, and stages for commit.
// POST /api/model/apply
func (s *Server) apiApplyModel(w http.ResponseWriter, r *http.Request) {
	if s.modelMgr == nil {
		apiError(w, "model manager not initialized", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		apiError(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var req ApplyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apiError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate all files from the model
	files := pf.GenerateFiles(&req.Model)

	// Stage each file and collect any errors
	var fileErrors []FileError
	staged := 0

	for _, f := range files {
		// Map generated paths to config file names
		name := pathToConfigName(f.Path)
		if name == "" {
			continue // Skip files we don't manage
		}

		// Validate the content first
		out, ok, err := s.store.CheckContent(r.Context(), name, []byte(f.Content))
		if err != nil {
			fileErrors = append(fileErrors, FileError{
				Path:  f.Path,
				Error: err.Error(),
			})
			continue
		}
		if !ok {
			fileErrors = append(fileErrors, FileError{
				Path:   f.Path,
				Error:  "validation failed",
				Output: out,
			})
			continue
		}

		// Stage the file
		if err := s.store.Stage(name, []byte(f.Content)); err != nil {
			fileErrors = append(fileErrors, FileError{
				Path:  f.Path,
				Error: err.Error(),
			})
			continue
		}
		staged++
	}

	// If all files staged successfully, save the model
	if len(fileErrors) == 0 {
		s.modelMgr.Set(&req.Model)
		if err := s.modelMgr.Save(); err != nil {
			apiJSON(w, ApplyResponse{
				Files:  files,
				Staged: staged,
				Error:  "files staged but failed to save model: " + err.Error(),
			})
			return
		}
	}

	resp := ApplyResponse{
		Files:  files,
		Staged: staged,
	}
	if len(fileErrors) > 0 {
		resp.Error = fmt.Sprintf("%d file(s) failed validation", len(fileErrors))
		resp.Details = fileErrors
	}

	apiJSON(w, resp)
}

// pathToConfigName maps a generated file path to a config file name.
func pathToConfigName(path string) string {
	switch path {
	case "/etc/pf.conf":
		return "pf.conf"
	case "/etc/dhcpd.conf":
		return "dhcpd.conf"
	case "/var/unbound/etc/unbound.conf":
		return "unbound.conf"
	case "/etc/ntpd.conf":
		return "ntpd.conf"
	case "/etc/myname":
		return "" // Not a managed config file
	case "/etc/mygate":
		return "" // Not a managed config file
	default:
		// hostname.* files
		if len(path) > 15 && path[:14] == "/etc/hostname." {
			return "hostname." + path[14:]
		}
		return ""
	}
}
