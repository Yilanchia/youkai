package ledger

import (
	"context"
	"encoding/json"
	"fmt"
)

// ChatMessage is one turn of the conversation, stored so a refresh does not lose it.
//
// What is deliberately absent: response bodies, headers, cookies, tokens. The
// conversation is stored for the operator's convenience; the target's words are
// never part of it (they are attacker-controlled, see ADR-005).
type ChatMessage struct {
	ID           int64           `json:"id"`
	EngagementID int64           `json:"engagement_id"`
	Role         string          `json:"role"`
	Content      string          `json:"content"`
	Cards        json.RawMessage `json:"cards,omitempty"`
	CreatedAt    string          `json:"created_at"`
}

// AppendChat stores one message and returns it.
func (s *Store) AppendChat(ctx context.Context, engagementID int64, role, content string, cards any) (ChatMessage, error) {
	if role != "user" && role != "assistant" {
		return ChatMessage{}, fmt.Errorf("ledger: chat role %q is not user/assistant", role)
	}
	var raw []byte
	if cards != nil {
		b, err := json.Marshal(cards)
		if err != nil {
			return ChatMessage{}, fmt.Errorf("ledger: encode cards: %w", err)
		}
		raw = b
	} else {
		raw = []byte("[]")
	}
	var m ChatMessage
	err := s.pool.QueryRow(ctx, `
		INSERT INTO chat_messages (engagement_id, role, content, cards)
		VALUES ($1,$2,$3,$4)
		RETURNING id, engagement_id, role, content, cards,
		          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || 'Z'`,
		engagementID, role, content, raw).
		Scan(&m.ID, &m.EngagementID, &m.Role, &m.Content, &m.Cards, &m.CreatedAt)
	if err != nil {
		return ChatMessage{}, fmt.Errorf("ledger: append chat: %w", err)
	}
	return m, nil
}

// ChatHistory returns the conversation in order.
func (s *Store) ChatHistory(ctx context.Context, engagementID int64, limit int) ([]ChatMessage, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, engagement_id, role, content, cards, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || 'Z'
		  FROM chat_messages WHERE engagement_id = $1
		 ORDER BY id DESC LIMIT $2`, engagementID, limit)
	if err != nil {
		return nil, fmt.Errorf("ledger: chat history: %w", err)
	}
	defer rows.Close()
	out := make([]ChatMessage, 0)
	for rows.Next() {
		var m ChatMessage
		if err := rows.Scan(&m.ID, &m.EngagementID, &m.Role, &m.Content, &m.Cards, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("ledger: scan chat: %w", err)
		}
		out = append(out, m)
	}
	// Newest-first query, oldest-first presentation.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}
