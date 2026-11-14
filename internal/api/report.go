package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"youkai/internal/gate"
	"youkai/internal/ledger"
	"youkai/internal/report"
)

// Report, snapshot, SARIF and disclosure endpoints.
//
// Every one of them is a pure read of the ledger followed by rendering: none of
// them can send a request to a target. That is what lets the report be the thing
// you hand over - it cannot have grown new evidence while you were not looking.

// loadBundle reads the ledger and grades it into a report bundle.
func (s *Server) loadBundle(r *http.Request, eng ledger.Engagement, generatedAt string) (report.Bundle, error) {
	ctx := r.Context()
	g, err := s.cfg.Store.Graph(ctx, eng.ID)
	if err != nil {
		return report.Bundle{}, err
	}
	audit, err := s.cfg.Store.AuditTail(ctx, eng.Name, 500)
	if err != nil {
		return report.Bundle{}, err
	}
	return report.Build(report.Input{
		Engagement:  eng.Name,
		Scope:       eng.Scope,
		Provider:    gate.Provider().Reason(),
		Stats:       g.Stats,
		Findings:    g.Findings,
		Facts:       g.Facts,
		Intents:     g.Intents,
		Audit:       audit,
		GeneratedAt: generatedAt,
	}), nil
}

// handleReport serves the bundle in one of three formats.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	// GeneratedAt is derived from the ledger, not from the clock, so two renders of
	// an unchanged ledger are byte-identical.
	b, err := s.loadBundle(r, eng, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	switch r.URL.Query().Get("format") {
	case "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.Markdown(b)))
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(report.HTML(b)))
	default:
		writeJSON(w, http.StatusOK, b)
	}
}

// handleSnapshots lists snapshots, or creates one on POST.
func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request, eng ledger.Engagement, tail []string) {
	switch {
	case len(tail) == 0 && r.Method == http.MethodGet:
		list, err := s.cfg.Store.ListReportSnapshots(r.Context(), eng.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if list == nil {
			list = []ledger.ReportSnapshot{}
		}
		writeJSON(w, http.StatusOK, list)
	case len(tail) == 0 && r.Method == http.MethodPost:
		s.createSnapshot(w, r, eng)
	case len(tail) == 1 && r.Method == http.MethodGet:
		id, err := parseID(tail[0])
		if err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		snap, err := s.cfg.Store.ReportSnapshot(r.Context(), eng.ID, id)
		if errors.Is(err, ledger.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "snapshot %d not found", id)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, snap)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET, or POST with no id")
	}
}

// createSnapshot pins the current projection and writes the HTML artefact.
func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	b, err := s.loadBundle(r, eng, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	raw, err := json.Marshal(b)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	sha, err := report.Hash(b)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	snap, err := s.cfg.Store.SaveReportSnapshot(r.Context(), eng.ID, sha, eng.Scope, raw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := map[string]any{"snapshot": snap, "sha256": sha}
	// The self-contained HTML is the human artefact; failing to write it must not
	// lose the snapshot, so the error is reported alongside.
	if path, err := s.writeReportArtefact(eng, sha, b); err != nil {
		out["artifact_error"] = err.Error()
	} else {
		out["artifact"] = path
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) writeReportArtefact(eng ledger.Engagement, sha string, b report.Bundle) (string, error) {
	dir := filepath.Join(s.cfg.ArtifactDir, artifactSlug(eng.Name), "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	short := sha
	if len(short) > 8 {
		short = short[:8]
	}
	path := filepath.Join(dir, "report-"+short+".html")
	if err := os.WriteFile(path, []byte(report.HTML(b)), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// handleSARIF exports SARIF 2.1.0.
func (s *Server) handleSARIF(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	b, err := s.loadBundle(r, eng, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	raw, err := report.SARIF(b)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleDisclosure renders the verified-only disclosure document.
func (s *Server) handleDisclosure(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	b, err := s.loadBundle(r, eng, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	scope := report.ParseScope(eng.Scope)

	var (
		doc  string
		rerr error
	)
	if r.URL.Query().Get("format") == "html" {
		doc, rerr = report.DisclosureHTML(b, scope)
	} else {
		doc, rerr = report.DisclosureMarkdown(b, scope)
	}
	if rerr != nil {
		var nov report.ErrNoVerified
		var noa report.ErrNoAuthorisation
		switch {
		case errors.As(rerr, &nov):
			// An empty shell would be worse than a clear no: say why.
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": rerr.Error(), "verified": 0,
				"hint": "先用 PATCH/POST 的 verdict 把发现确认为 verified,披露包只收已证发现",
			})
		case errors.As(rerr, &noa):
			writeErr(w, http.StatusPreconditionFailed, "%v", rerr)
		default:
			writeErr(w, http.StatusInternalServerError, "%v", rerr)
		}
		return
	}
	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc))
}

// artifactSlug makes an engagement name safe as a directory component.
func artifactSlug(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "engagement"
	}
	return out
}
