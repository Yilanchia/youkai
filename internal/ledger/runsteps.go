package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RunStep is one narrated step of a run, persisted.
//
// Persisting them (rather than only broadcasting) is what makes the stream survive
// a refresh, a reconnect and a closed laptop: the operator can come back and read
// what happened while they were away. The rows are append-only like everything else
// that is evidence.
type RunStep struct {
	RunID      int64    `json:"run_id"`
	Seq        int      `json:"seq"`
	Phase      string   `json:"phase"`
	IntentID   int64    `json:"intent_id,omitempty"`
	Capability string   `json:"capability,omitempty"`
	Tier       int      `json:"tier,omitempty"`
	Target     string   `json:"target,omitempty"`
	Status     string   `json:"status,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Facts      int      `json:"facts,omitempty"`
	Findings   int      `json:"findings,omitempty"`
	RequestID  string   `json:"request_id,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Stop       string   `json:"stop,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	At         string   `json:"at,omitempty"`
}

// AppendRunSteps stores a batch of narrated steps and returns them with their
// sequence numbers filled in.
//
// The sequence is allocated HERE, per engagement, under an advisory lock: a run and
// a hand-approved step can append at the same time, and both must land in one
// readable order without fighting over the primary key.
//
// It never updates an existing row: a step happened once, and rewriting the record
// of it would be the same class of mistake as editing a finding.
func (s *Store) AppendRunSteps(ctx context.Context, engagementID int64, steps []RunStep) ([]RunStep, error) {
	if len(steps) == 0 {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, engagementID); err != nil {
		return nil, fmt.Errorf("ledger: run step lock: %w", err)
	}
	var last int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq),0) FROM run_steps WHERE engagement_id=$1`, engagementID).Scan(&last); err != nil {
		return nil, err
	}
	out := make([]RunStep, 0, len(steps))
	for _, st := range steps {
		last++
		st.Seq = last
		tags, err := json.Marshal(st.Tags)
		if err != nil {
			return nil, fmt.Errorf("ledger: run step tags: %w", err)
		}
		if len(st.Tags) == 0 {
			tags = []byte("[]")
		}
		at := st.At
		if at == "" {
			at = time.Now().UTC().Format(time.RFC3339)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO run_steps
				(engagement_id, run_id, seq, phase, intent_id, capability, tier, target,
				 status, summary, facts, findings, request_id, reason, stop, tags, at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			engagementID, st.RunID, st.Seq, st.Phase, st.IntentID, st.Capability, st.Tier,
			st.Target, st.Status, st.Summary, st.Facts, st.Findings, st.RequestID,
			st.Reason, st.Stop, tags, at); err != nil {
			return nil, fmt.Errorf("ledger: append run step: %w", err)
		}
		out = append(out, st)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// RunStepsSince returns the narrated steps after a sequence number, oldest first.
//
// `since` is the last seq the caller has seen; 0 means "from the beginning". The
// limit is a ring: a very long run still returns the most recent slice rather than
// a megabyte of history.
func (s *Store) RunStepsSince(ctx context.Context, engagementID int64, since int, limit int) ([]RunStep, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT run_id, seq, phase, intent_id, capability, tier, target, status,
		       summary, facts, findings, request_id, reason, stop, tags, at
		  FROM run_steps
		 WHERE engagement_id = $1 AND seq > $2
		 ORDER BY seq ASC
		 LIMIT $3`, engagementID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("ledger: run steps: %w", err)
	}
	defer rows.Close()
	var out []RunStep
	for rows.Next() {
		var st RunStep
		var tags []byte
		var at time.Time
		if err := rows.Scan(&st.RunID, &st.Seq, &st.Phase, &st.IntentID, &st.Capability,
			&st.Tier, &st.Target, &st.Status, &st.Summary, &st.Facts, &st.Findings,
			&st.RequestID, &st.Reason, &st.Stop, &tags, &at); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &st.Tags)
		st.At = at.UTC().Format(time.RFC3339)
		out = append(out, st)
	}
	return out, rows.Err()
}

// NextRunStepSeq is used by callers that need to publish a step before storing it.
func (s *Store) NextRunStepSeq(ctx context.Context, engagementID int64) (int, error) {
	var next int
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq),0)+1 FROM run_steps WHERE engagement_id=$1`, engagementID).Scan(&next)
	if err != nil {
		return 0, err
	}
	return next, nil
}
