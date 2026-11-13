package hands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ArtifactRef is a registered sample: the graph anchor value plus where it lives.
type ArtifactRef struct {
	// Value is the graph anchor, e.g. "artifact:C:\samples\a.exe".
	Value string `json:"value"`
	// Path is the local path (empty for a URL artifact that was not downloaded).
	Path string `json:"path,omitempty"`
	// URL is the origin URL when Fairy learned about it from a scan.
	URL string `json:"url,omitempty"`
	// LedgerID is whatever identifier Fairy returned, for cross-reference.
	LedgerID string `json:"ledger_id,omitempty"`
}

// RegisterLocalArtifact registers a sample that is ALREADY on disk with Fairy's
// ledger, without downloading anything.
//
// This is the "youkai 不自己拉" rule: youkai may point Fairy at a path, but a
// download is a human decision (see PlanDownload).
func (s *Set) RegisterLocalArtifact(ctx context.Context, project, path, note string) (ArtifactRef, error) {
	ref := ArtifactRef{Value: "artifact:" + path, Path: path}
	if strings.TrimSpace(path) == "" {
		return ref, fmt.Errorf("register artifact: empty path")
	}
	res, err := s.Call(ctx, Fairy, "fairy_handoff", map[string]any{
		"project": project,
		"path":    path,
		"note":    note,
	})
	if err != nil {
		return ref, fmt.Errorf("fairy_handoff(path): %w", err)
	}
	if res.IsError {
		return ref, fmt.Errorf("fairy_handoff(path) refused: %s", firstLine(res.Text()))
	}
	ref.LedgerID = extractID(res.Text())
	return ref, nil
}

// DownloadPlan is the exact call youkai refuses to make on its own.
//
// Downloading a binary into an engagement is a proof-grade act: it puts attacker
// controlled bytes on the operator's disk. youkai stops, says exactly what it
// would send, and hands it to Fairy's high-auth path.
type DownloadPlan struct {
	Project string `json:"project"`
	URL     string `json:"url"`
	Call    string `json:"call"`
	Reason  string `json:"reason"`
	// HandFairyCall is the literal tool call a human may approve.
	HandFairyCall string `json:"hand_fairy_call"`
}

// PlanDownload describes, without performing, the tier-2 handoff download.
func PlanDownload(project, url string) DownloadPlan {
	return DownloadPlan{
		Project: project,
		URL:     url,
		Call:    fmt.Sprintf("fairy_handoff(project=%q, url=%q, confirm=true)", project, url),
		Reason: "downloading a sample puts attacker-controlled bytes on disk; " +
			"youkai never pulls, a human approves this once through Fairy",
		HandFairyCall: "fairy_handoff",
	}
}

// IngestIntoFairy mirrors an observation into Fairy's ledger so the authority
// stays in one place (ADR-002: Fairy holds scope/assets; youkai holds the graph).
//
// Idempotency is Fairy's: payloads carry a source_run_id, and Fairy's ingest is
// idempotent on it. Best effort by contract - the caller records the outcome.
func (s *Set) IngestIntoFairy(ctx context.Context, project, source string, payload any) (bool, string) {
	res, err := s.Call(ctx, Fairy, "fairy_ingest", map[string]any{
		"project": project,
		"source":  source,
		"payload": payload,
	})
	if err != nil {
		return false, "fairy_ingest: " + err.Error()
	}
	if res.IsError {
		return false, "fairy_ingest refused: " + firstLine(res.Text())
	}
	return true, "ingested as " + source
}

// HandoffURL registers a URL artifact (metadata only, no download) and returns
// the anchor the graph should use. Refuses anything that would fetch the bytes.
func (s *Set) HandoffURL(ctx context.Context, project, url, note string) (ArtifactRef, error) {
	ref := ArtifactRef{Value: "artifact:" + url, URL: url}
	res, err := s.Call(ctx, Fairy, "fairy_handoff", map[string]any{
		"project": project,
		"url":     url,
		"note":    note,
		// confirm is deliberately omitted: registration only.
	})
	if err != nil {
		return ref, fmt.Errorf("fairy_handoff(url): %w", err)
	}
	if res.IsError {
		return ref, fmt.Errorf("fairy_handoff(url) refused: %s", firstLine(res.Text()))
	}
	ref.LedgerID = extractID(res.Text())
	return ref, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}

// extractID pulls a plausible ledger id out of a hand result without pinning the
// exact shape of Fairy's reply.
func extractID(text string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return ""
	}
	for _, key := range []string{"id", "artifact_id", "asset_id", "path", "sha256"} {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	if inner, ok := m["artifact"].(map[string]any); ok {
		for _, key := range []string{"id", "path", "sha256"} {
			if s, ok := inner[key].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
