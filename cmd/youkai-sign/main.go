// Command youkai-sign signs a mandate, on the operator's machine.
//
// It exists as a SEPARATE binary on purpose: youkaid verifies signatures and has
// no signing code linked into it, so "youkai approved itself" is not representable
// even if the server is compromised. The key comes from the environment and never
// touches youkai's config, database, or logs.
//
// Usage:
//
//	$env:FAIRY_AUTH_KEY = "…"
//	youkai-sign -draft mandate.json -out mandate.signed.json
//
// The draft is the JSON you were shown (assets, actions, max_requests, expiry).
// Signing covers exactly those bytes-after-canonicalisation: change one field and
// the signature no longer verifies.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	draftPath := flag.String("draft", "", "path to the draft JSON (the mandate definition)")
	outPath := flag.String("out", "", "where to write the signed record (default stdout)")
	flag.Parse()

	key := strings.TrimSpace(os.Getenv("FAIRY_AUTH_KEY"))
	if len(key) < 16 {
		fail("FAIRY_AUTH_KEY must be set and at least 16 characters")
	}
	if *draftPath == "" {
		fail("need -draft <file>")
	}
	raw, err := os.ReadFile(*draftPath)
	if err != nil {
		fail("read draft: " + err.Error())
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		fail("parse draft: " + err.Error())
	}
	if _, ok := payload["basis"]; !ok {
		fail("draft has no basis: a mandate must say what authorises it")
	}
	if _, ok := payload["expires_at"]; !ok {
		fail("draft has no expires_at: open-ended mandates are refused")
	}
	if _, ok := payload["max_requests"]; !ok {
		fail("draft has no max_requests: a mandate without a budget is refused")
	}

	canonical, err := canonicalJSON(payload)
	if err != nil {
		fail("canonicalise: " + err.Error())
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	record := map[string]any{
		"schema":    "FairyHighAuth/v1",
		"payload":   payload,
		"signature": hex.EncodeToString(mac.Sum(nil)),
	}
	out, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		fail("encode: " + err.Error())
	}
	if *outPath == "" {
		fmt.Println(string(out))
		return
	}
	if err := os.WriteFile(*outPath, append(out, '\n'), 0o600); err != nil {
		fail("write: " + err.Error())
	}
	fmt.Printf("signed → %s\n", *outPath)
	fmt.Printf("payload fingerprint: %s\n", shortHash(canonical))
	fmt.Println("the signature is over these exact fields; editing any of them invalidates it")
}

// canonicalJSON matches the verifier byte-for-byte: sorted keys, no HTML escaping,
// compact separators. Kept as a local copy so youkaid never links a signer.
func canonicalJSON(m map[string]any) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalNoEscape(k)
		if err != nil {
			return "", err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(m[k])
		if err != nil {
			return "", err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "youkai-sign: "+msg)
	os.Exit(1)
}
