package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"youkai/internal/discipline"
)

// signRecord signs a payload the way the operator's youkai-sign does: canonical
// JSON in, HMAC-SHA256 out. Having the test do it keeps the verifier honest.
func signRecord(t *testing.T, key string, payload map[string]any) map[string]any {
	t.Helper()
	canonical, err := discipline.CanonicalPayload(payload)
	if err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	return map[string]any{
		"schema": discipline.HighAuthSchema, "payload": payload,
		"signature": hex.EncodeToString(mac.Sum(nil)),
	}
}

func mandatePayload(t *testing.T, engName string, assets, actions []string, maxReq int, expires time.Time) map[string]any {
	t.Helper()
	return map[string]any{
		"tier": "highest", "basis": "self-hosted lab, signed by the operator",
		"approver": "alice", "assets": assets, "actions": actions,
		"max_requests": float64(maxReq),
		"issued_at":    time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		"expires_at":   expires.UTC().Format(time.RFC3339),
		"nonce":        engName + "-nonce",
	}
}

// TestMandateMustBeSignedToActivate: the whole point is that youkai cannot sign.
func TestMandateMustBeSignedToActivate(t *testing.T) {
	const key = "test-high-auth-key-0123456789"
	t.Setenv(discipline.HighAuthKeyEnv, key)
	f := newFixture(t, key)
	path := fmt.Sprintf("/api/engagements/%d/mandate/activate", f.eng.ID)

	payload := mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"read-only", "tier2:param"}, 300, time.Now().Add(time.Hour))

	// No signature at all.
	code, body := f.do(t, http.MethodPost, path, payload, nil)
	if code != http.StatusForbidden {
		t.Fatalf("unsigned mandate = %d %v, want 403", code, body)
	}

	// A signature made with a different key.
	other := signRecord(t, "a-different-key-0123456789", payload)
	code, body = f.do(t, http.MethodPost, path, other, nil)
	if code != http.StatusForbidden {
		t.Fatalf("wrongly-signed mandate = %d %v, want 403", code, body)
	}

	// Tampering after signing must break it: change the budget.
	good := signRecord(t, key, payload)
	payload["max_requests"] = float64(100000)
	code, body = f.do(t, http.MethodPost, path, good, nil)
	if code != http.StatusForbidden {
		t.Fatalf("tampered mandate = %d %v, want 403", code, body)
	}
}

// TestMandateActivationChecksEveryField: budget, expiry, scope, and classes.
func TestMandateActivationChecksEveryField(t *testing.T) {
	const key = "test-high-auth-key-0123456789"
	t.Setenv(discipline.HighAuthKeyEnv, key)
	f := newFixture(t, key)
	path := fmt.Sprintf("/api/engagements/%d/mandate/activate", f.eng.ID)

	cases := []struct {
		name    string
		payload map[string]any
		want    int
	}{
		{"no budget", mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:param"}, 0, time.Now().Add(time.Hour)), http.StatusBadRequest},
		{"expired", mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:param"}, 100, time.Now().Add(-time.Hour)), http.StatusForbidden},
		{"unknown class", mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:everything"}, 100, time.Now().Add(time.Hour)), http.StatusForbidden},
		{"outside the passport", mandatePayload(t, f.eng.Name, []string{"example.com"}, []string{"tier2:param"}, 100, time.Now().Add(time.Hour)), http.StatusForbidden},
		{"bare host covers the port", mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:param"}, 100, time.Now().Add(time.Hour)), http.StatusCreated},
		{"explicit wrong port", mandatePayload(t, f.eng.Name, []string{"127.0.0.1:9"}, []string{"tier2:param"}, 100, time.Now().Add(time.Hour)), http.StatusForbidden},
		{"only read-only", mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"read-only"}, 100, time.Now().Add(time.Hour)), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := signRecord(t, key, tc.payload)
			code, body := f.do(t, http.MethodPost, path, rec, nil)
			if code != tc.want {
				t.Fatalf("%s: %d %v, want %d", tc.name, code, body, tc.want)
			}
		})
	}
}

// TestMandateLifecycleOverHTTP: activate → visible → stop → gone.
func TestMandateLifecycleOverHTTP(t *testing.T) {
	const key = "test-high-auth-key-0123456789"
	t.Setenv(discipline.HighAuthKeyEnv, key)
	f := newFixture(t, key)
	base := fmt.Sprintf("/api/engagements/%d/mandate", f.eng.ID)

	code, body := f.do(t, http.MethodGet, base, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %v", code, body)
	}
	if active, _ := body["active"].(bool); active {
		t.Fatal("a fresh engagement reports an active mandate")
	}

	payload := mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"read-only", "tier2:param"}, 300, time.Now().Add(time.Hour))
	code, body = f.do(t, http.MethodPost, base+"/activate", signRecord(t, key, payload), nil)
	if code != http.StatusCreated {
		t.Fatalf("activate: %d %v", code, body)
	}

	code, body = f.do(t, http.MethodGet, base, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("get after activate: %d %v", code, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("mandate not active after activation: %v", body)
	}
	if remaining, _ := body["remaining"].(float64); remaining != 300 {
		t.Fatalf("remaining = %v, want 300", body["remaining"])
	}

	code, body = f.do(t, http.MethodPost, base+"/stop", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("stop: %d %v", code, body)
	}
	code, body = f.do(t, http.MethodGet, base, nil, nil)
	if active, _ := body["active"].(bool); active {
		t.Fatalf("stopped mandate still active: %v", body)
	}
}

// TestMandateWithoutKeyRefusesToVerify: no key, no activation - not even a
// correctly signed record, because there is nothing to verify against.
func TestMandateWithoutKeyRefusesToVerify(t *testing.T) {
	t.Setenv(discipline.HighAuthKeyEnv, "")
	f := newFixture(t, "")
	payload := mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:param"}, 100, time.Now().Add(time.Hour))
	code, body := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/mandate/activate", f.eng.ID),
		signRecord(t, "whatever-key-0123456789", payload), nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("activation without FAIRY_AUTH_KEY = %d %v, want 503", code, body)
	}
}

// TestMandateRouteRejectsUnknownSubpaths keeps the surface small.
func TestMandateRouteRejectsUnknownSubpaths(t *testing.T) {
	f := newFixture(t, "")
	code, _ := f.do(t, http.MethodGet, fmt.Sprintf("/api/engagements/%d/mandate/sign", f.eng.ID), nil, nil)
	if code != http.StatusNotFound {
		t.Fatalf("GET …/mandate/sign = %d, want 404 (youkai does not sign)", code)
	}
}

// TestMandateNeedsThePassportSwitch: a signed mandate cannot do what the passport
// forbids. Without this check the run stalls three steps later with a confusing
// capability error instead of at the signature.
func TestMandateNeedsThePassportSwitch(t *testing.T) {
	const key = "test-high-auth-key-0123456789"
	t.Setenv(discipline.HighAuthKeyEnv, key)
	f := newFixture(t, key)

	// Turn the class off in the STORED passport: the handler reads the engagement
	// from the store, so this is the real "operator did not enable it" case.
	code, body := f.do(t, http.MethodPut, fmt.Sprintf("/api/engagements/%d/scope", f.eng.ID), map[string]any{
		"scope": map[string]any{
			"include": []string{"127.0.0.1"}, "basis": "self-hosted lab", "operator": "t",
			"allow_private": true, "allow_active_probes": false,
		}, "updated_by": "test",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("update scope: %d %v", code, body)
	}

	payload := mandatePayload(t, f.eng.Name, []string{"127.0.0.1"}, []string{"tier2:param"}, 100, time.Now().Add(time.Hour))
	code, body = f.do(t, http.MethodPost,
		fmt.Sprintf("/api/engagements/%d/mandate/activate", f.eng.ID),
		signRecord(t, key, payload), nil)
	if code != http.StatusForbidden {
		t.Fatalf("mandate without the passport switch = %d %v, want 403", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "allow_active_probes") {
		t.Fatalf("error does not name the missing switch: %q", msg)
	}
}

var _ = json.Marshal
