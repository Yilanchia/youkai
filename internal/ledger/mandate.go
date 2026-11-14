package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Mandates are the signed fences from ADR-005.
//
// A mandate says: within THIS scope, youkai may run these CLASSES of tier-2 work
// without stopping at every step, up to this request budget, until this time.
//
// Two properties matter more than the feature:
//
//   - it is data, not a memory flag. Activating writes a row; stopping writes a
//     column; expiry is derived from the clock. Nothing an LLM says can flip it.
//   - it is a signed record. The row stores the exact payload and signature that
//     were verified, so an auditor can re-verify it later without trusting us.

// Mandate is one stored authorisation.
type Mandate struct {
	ID           int64           `json:"id"`
	EngagementID int64           `json:"engagement_id"`
	Payload      json.RawMessage `json:"payload"`
	Signature    string          `json:"signature"`
	Assets       []string        `json:"assets"`
	Classes      []string        `json:"classes"`
	MaxRequests  int             `json:"max_requests"`
	ExpiresAt    time.Time       `json:"expires_at"`
	ActivatedAt  time.Time       `json:"activated_at"`
	StoppedAt    *time.Time      `json:"stopped_at,omitempty"`
	Approver     string          `json:"approver"`
	Basis        string          `json:"basis"`
}

// Active reports whether the mandate is in force right now.
func (m Mandate) Active(now time.Time) bool {
	return m.StoppedAt == nil && now.Before(m.ExpiresAt)
}

// CoversClass reports whether this mandate pre-authorises an autonomy class.
func (m Mandate) CoversClass(class string) bool {
	for _, c := range m.Classes {
		if c == class {
			return true
		}
	}
	return false
}

// SaveMandate stores an already-verified mandate and returns it.
func (s *Store) SaveMandate(ctx context.Context, engagementID int64, payload json.RawMessage, signature string, assets, classes []string, maxRequests int, expiresAt time.Time, approver, basis string) (Mandate, error) {
	if len(assets) == 0 || len(classes) == 0 {
		return Mandate{}, fmt.Errorf("ledger: a mandate needs assets and classes")
	}
	if maxRequests <= 0 {
		return Mandate{}, fmt.Errorf("ledger: a mandate needs a positive request budget")
	}
	if expiresAt.IsZero() {
		return Mandate{}, fmt.Errorf("ledger: a mandate needs an expiry")
	}
	var m Mandate
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mandates
		  (engagement_id, payload, signature, assets, classes, max_requests, expires_at, approver, basis)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, engagement_id, payload, signature, assets, classes, max_requests, expires_at, activated_at, approver, basis`,
		engagementID, []byte(payload), signature, nonNilStrings(assets), nonNilStrings(classes),
		maxRequests, expiresAt, approver, basis).
		Scan(&m.ID, &m.EngagementID, &m.Payload, &m.Signature, &m.Assets, &m.Classes,
			&m.MaxRequests, &m.ExpiresAt, &m.ActivatedAt, &m.Approver, &m.Basis)
	if err != nil {
		return Mandate{}, fmt.Errorf("ledger: save mandate: %w", err)
	}
	return m, nil
}

// ActiveMandate returns the mandate in force, or ErrNotFound.
//
// Stopped mandates and expired ones are simply not active: there is no cache to
// invalidate, which is what makes "stop" instant.
func (s *Store) ActiveMandate(ctx context.Context, engagementID int64) (Mandate, error) {
	var m Mandate
	err := s.pool.QueryRow(ctx, `
		SELECT id, engagement_id, payload, signature, assets, classes, max_requests,
		       expires_at, activated_at, stopped_at, approver, basis
		  FROM mandates
		 WHERE engagement_id = $1 AND stopped_at IS NULL AND expires_at > now()
		 ORDER BY id DESC LIMIT 1`, engagementID).
		Scan(&m.ID, &m.EngagementID, &m.Payload, &m.Signature, &m.Assets, &m.Classes,
			&m.MaxRequests, &m.ExpiresAt, &m.ActivatedAt, &m.StoppedAt, &m.Approver, &m.Basis)
	if errors.Is(err, pgx.ErrNoRows) {
		return Mandate{}, ErrNotFound
	}
	if err != nil {
		return Mandate{}, fmt.Errorf("ledger: active mandate: %w", err)
	}
	return m, nil
}

// StopMandate revokes every active mandate of an engagement. Returns how many.
func (s *Store) StopMandate(ctx context.Context, engagementID int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE mandates SET stopped_at = now()
		 WHERE engagement_id = $1 AND stopped_at IS NULL`, engagementID)
	if err != nil {
		return 0, fmt.Errorf("ledger: stop mandate: %w", err)
	}
	return tag.RowsAffected(), nil
}

// MandateUsage counts the requests actually sent since a mandate was activated.
//
// It is the budget enforcement point: the number comes from the audit log, i.e.
// from requests that really left the machine, not from what a planner intended.
func (s *Store) MandateUsage(ctx context.Context, engagement string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log
		 WHERE engagement = $1 AND ts >= $2 AND verdict = 'allowed'`, engagement, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("ledger: mandate usage: %w", err)
	}
	return n, nil
}
