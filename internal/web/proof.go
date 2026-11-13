package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// DOM-context judgement for a reflected marker.
//
// A real browser is the only way to judge the *DOM* context. This build has no
// browser backend (see browser.go), so the judgement is made on the raw response:
// where does the marker sit in the HTML source, and is a CSP present? That is
// enough to raise or lower a candidate, and it is honest about what it is. The
// fact stays a candidate; nothing here proves execution.

// newMarker returns a marker with no shell/HTML metacharacters, so it can detect
// reflection without being a payload.
func newMarker(prefix string) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return prefix + "0000000000000000"
	}
	return prefix + hex.EncodeToString(raw[:])
}

func runProof(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	param, err := requiredString(args, "param")
	if err != nil {
		return ledger.Observation{}, err
	}
	marker := argRawString(args, "marker")
	if marker == "" {
		marker = newMarker("youkai")
	}
	target, err := withQueryParam(rawURL, param, marker)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: proof: %w", err)
	}

	res, err := do(ctx, env, discipline.Request{
		Method:          "GET",
		URL:             target,
		Headers:         argStringMap(args, "headers"),
		Purpose:         "proof",
		FollowRedirects: argBool(args, "follow_redirects", true),
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: proof: %w", err)
	}

	b := newObs()
	b.requestID(res.RequestID)

	contextName := classifyReflection(res.Text(), marker)
	csp := headerGet(res.Header, "Content-Security-Policy")
	// Only direct reflection can be judged on the source; the marker has to be
	// present, and the context name says where it landed.
	executable := contextName == contextScript || contextName == contextEventAttr
	attributeContext := contextName == contextAttribute

	tags := []string{"reflection", contextName}
	if (executable || attributeContext) && csp == "" {
		// No CSP and a script/attribute landing: the strongest candidate this
		// build can honestly produce. Still not a finding.
		tags = append(tags, "xss-context", "no-csp")
	}
	if csp != "" {
		tags = append(tags, "csp-present")
	}

	ev := respEvidence(res)
	ev["url"] = target
	ev["marker"] = marker
	ev["context"] = contextName
	ev["reflected"] = contextName != contextNotReflected
	ev["csp_present"] = csp != ""
	if csp != "" {
		ev["csp"] = truncateText(csp, 160)
	}
	if contextName != contextNotReflected {
		ev["interpretation"] = "标记落在 " + contextName + ";只判定上下文,不生成载荷,执行证明需人工在浏览器完成"
	}
	b.fact("反射上下文:"+contextName, ev, tags...)
	b.setSummary(fmt.Sprintf("proof %s param=%s -> %s (CSP:%t)", rawURL, param, contextName, csp != ""))
	return b.obs, nil
}

// truncateText bounds a string without splitting a UTF-8 rune.
func truncateText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
