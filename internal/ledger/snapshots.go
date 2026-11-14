package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Report snapshots pin one projection of the ledger.
//
// Why pin it at all: the ledger keeps growing, so "the report I sent to the vendor
// last Tuesday" is otherwise unreproducible. A snapshot stores the exact bundle,
// the passport that was in force, and a content hash. Like the audit log it is
// append-only (a trigger refuses UPDATE/DELETE), because a snapshot you can edit
// proves nothing.

// ReportSnapshot is one immutable report.
type ReportSnapshot struct {
	ID            int64           `json:"id"`
	EngagementID  int64           `json:"engagement_id"`
	CreatedAt     time.Time       `json:"created_at"`
	ContentSHA256 string          `json:"content_sha256"`
	ScopeSnapshot json.RawMessage `json:"scope_snapshot,omitempty"`
	Bundle        json.RawMessage `json:"bundle,omitempty"`
}

// SaveReportSnapshot appends a snapshot.
func (s *Store) SaveReportSnapshot(ctx context.Context, engagementID int64, sha string, scope, bundle json.RawMessage) (ReportSnapshot, error) {
	if sha == "" {
		return ReportSnapshot{}, fmt.Errorf("ledger: snapshot needs a content hash")
	}
	if len(scope) == 0 {
		scope = json.RawMessage(`{}`)
	}
	if !json.Valid(scope) || !json.Valid(bundle) {
		return ReportSnapshot{}, fmt.Errorf("ledger: snapshot payload is not valid JSON")
	}
	var snap ReportSnapshot
	err := s.pool.QueryRow(ctx, `
		INSERT INTO report_snapshots (engagement_id, content_sha256, scope_snapshot, bundle)
		VALUES ($1,$2,$3,$4)
		RETURNING id, engagement_id, created_at, content_sha256`,
		engagementID, sha, []byte(scope), []byte(bundle)).
		Scan(&snap.ID, &snap.EngagementID, &snap.CreatedAt, &snap.ContentSHA256)
	if err != nil {
		return ReportSnapshot{}, fmt.Errorf("ledger: save snapshot: %w", err)
	}
	snap.ScopeSnapshot = scope
	snap.Bundle = bundle
	return snap, nil
}

// ListReportSnapshots returns snapshots newest first, without the bundles (the
// list view only needs the anchor).
func (s *Store) ListReportSnapshots(ctx context.Context, engagementID int64) ([]ReportSnapshot, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, engagement_id, created_at, content_sha256
		  FROM report_snapshots WHERE engagement_id=$1
		 ORDER BY id DESC LIMIT 200`, engagementID)
	if err != nil {
		return nil, fmt.Errorf("ledger: list snapshots: %w", err)
	}
	defer rows.Close()
	var out []ReportSnapshot
	for rows.Next() {
		var snap ReportSnapshot
		if err := rows.Scan(&snap.ID, &snap.EngagementID, &snap.CreatedAt, &snap.ContentSHA256); err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

// ReportSnapshot loads one snapshot, bundle included.
func (s *Store) ReportSnapshot(ctx context.Context, engagementID, id int64) (ReportSnapshot, error) {
	var snap ReportSnapshot
	var scope, bundle []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, engagement_id, created_at, content_sha256, scope_snapshot, bundle
		  FROM report_snapshots WHERE engagement_id=$1 AND id=$2`, engagementID, id).
		Scan(&snap.ID, &snap.EngagementID, &snap.CreatedAt, &snap.ContentSHA256, &scope, &bundle)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReportSnapshot{}, ErrNotFound
	}
	if err != nil {
		return ReportSnapshot{}, err
	}
	snap.ScopeSnapshot = scope
	snap.Bundle = bundle
	return snap, nil
}
