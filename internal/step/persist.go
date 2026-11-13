package step

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"youkai/internal/graph"
)

// persisted is the on-disk form of a stepping session.
//
// Why persist at all: the design requires one action per human decision, which
// means the proposal the operator is looking at must survive between command
// invocations. Only the proposal, the pending approval, and the executed records
// are stored - never credentials, never response bodies.
type persisted struct {
	Nonce    string    `json:"nonce"`
	State    State     `json:"state"`
	Index    int       `json:"index"`
	Project  string    `json:"project"`
	Proposal *Proposal `json:"proposal,omitempty"`
	Approval *Approval `json:"approval,omitempty"`
	Records  []Record  `json:"records,omitempty"`
	StopNote string    `json:"stop_note,omitempty"`
}

// DefaultStatePath is where the CLI keeps the session, relative to the workspace.
const DefaultStatePath = ".youkai/step/session.json"

// Save writes the session state (0600: it names who authorised what).
func (s *Session) Save(path string) error {
	s.mu.Lock()
	p := persisted{
		Nonce:    s.nonce,
		State:    s.state,
		Index:    s.index,
		Project:  s.project,
		Proposal: s.proposal,
		Approval: s.approval,
		Records:  append([]Record(nil), s.records...),
		StopNote: s.stopNote,
	}
	s.mu.Unlock()

	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Restore loads a saved session into memory. A missing file yields a fresh
// session rather than an error: the first step is not a resume.
func Restore(path string, owner *graph.Owner, hands Hands, project string) (*Session, error) {
	s := New(owner, hands, project)

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("step state %s: %w", path, err)
	}
	s.mu.Lock()
	if p.Nonce != "" {
		s.nonce = p.Nonce
	}
	s.state = p.State
	s.index = p.Index
	if p.Project != "" {
		s.project = p.Project
	}
	s.proposal = p.Proposal
	s.approval = p.Approval
	s.records = p.Records
	s.stopNote = p.StopNote
	s.mu.Unlock()
	return s, nil
}
