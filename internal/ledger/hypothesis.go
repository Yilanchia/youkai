package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Hypotheses are the whitebox package's output: a lead, not a finding.
//
// The ladder is hypothesis -> candidate -> verified, and this type only ever sits on
// the first rung. It exists as its own table (rather than a fact) because the engine
// needs to ask "which leads are still open?" and the report needs to list them
// separately, under a heading that says plainly they are not findings.
type Hypothesis struct {
	ID           int64     `json:"id"`
	EngagementID int64     `json:"engagement_id"`
	Kind         string    `json:"kind"`  // sink / missing-authz
	Entry        string    `json:"entry"` // "GET /search"
	Param        string    `json:"param"`
	Sink         string    `json:"sink"`
	Path         string    `json:"path"`
	Confidence   string    `json:"confidence"`
	Note         string    `json:"note"`
	File         string    `json:"file"`
	Line         int       `json:"line"`
	State        string    `json:"state"` // open / probing / unconfirmed / candidate
	CreatedAt    time.Time `json:"created_at"`
}

// Hypothesis states.
const (
	HypothesisOpen        = "open"
	HypothesisProbing     = "probing"
	HypothesisUnconfirmed = "unconfirmed"
	HypothesisCandidate   = "candidate"
)

// SaveHypotheses stores a batch, skipping ones already recorded for this engagement
// (same kind + entry + param + sink + path). It returns how many were new.
func (s *Store) SaveHypotheses(ctx context.Context, engagementID int64, hs []Hypothesis) (int, error) {
	if len(hs) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	saved := 0
	for _, h := range hs {
		if h.Confidence == "" {
			h.Confidence = "code-only"
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO hypotheses
			  (engagement_id, kind, entry, param, sink, path, confidence, note, file, line, state)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open')
			ON CONFLICT (engagement_id, kind, entry, param, sink, path) DO NOTHING`,
			engagementID, h.Kind, h.Entry, h.Param, h.Sink, h.Path, h.Confidence, h.Note, h.File, h.Line)
		if err != nil {
			return saved, fmt.Errorf("ledger: save hypothesis: %w", err)
		}
		saved += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return saved, err
	}
	return saved, nil
}

// ListHypotheses returns the leads for an engagement, oldest first.
func (s *Store) ListHypotheses(ctx context.Context, engagementID int64, state string) ([]Hypothesis, error) {
	q := `SELECT id, engagement_id, kind, entry, param, sink, path, confidence, note, file, line, state, created_at
	        FROM hypotheses WHERE engagement_id = $1`
	args := []any{engagementID}
	if state != "" {
		q += ` AND state = $2`
		args = append(args, state)
	}
	q += ` ORDER BY id`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("ledger: list hypotheses: %w", err)
	}
	defer rows.Close()
	out := make([]Hypothesis, 0)
	for rows.Next() {
		var h Hypothesis
		if err := rows.Scan(&h.ID, &h.EngagementID, &h.Kind, &h.Entry, &h.Param, &h.Sink, &h.Path,
			&h.Confidence, &h.Note, &h.File, &h.Line, &h.State, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetHypothesisState moves one lead along the ladder. It refuses candidate unless
// the note carries the evidence that got it there: a state change with no reason is
// how "code looked scary" turns into "we reported a bug".
func (s *Store) SetHypothesisState(ctx context.Context, engagementID, id int64, state, note string) error {
	switch state {
	case HypothesisOpen, HypothesisProbing, HypothesisUnconfirmed, HypothesisCandidate:
	default:
		return fmt.Errorf("ledger: unknown hypothesis state %q", state)
	}
	if state == HypothesisCandidate && len([]rune(note)) < 12 {
		return fmt.Errorf("ledger: a hypothesis becomes a candidate only with evidence (note too short)")
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE hypotheses SET state = $3, note = CASE WHEN $4 = '' THEN note ELSE note || ' | ' || $4 END
		 WHERE engagement_id = $1 AND id = $2`, engagementID, id, state, note)
	if err != nil {
		return fmt.Errorf("ledger: set hypothesis state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ledger: hypothesis %d not found", id)
	}
	return nil
}

// HypothesesForGraph returns the leads for the report/graph payload.
func (s *Store) HypothesesForGraph(ctx context.Context, engagementID int64) (json.RawMessage, error) {
	hs, err := s.ListHypotheses(ctx, engagementID, "")
	if err != nil {
		return nil, err
	}
	return json.Marshal(hs)
}
