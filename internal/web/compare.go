package web

import (
	"context"
	"fmt"
	"math"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Dual-account comparison.
//
// The capability answers one question: can identity B see what identity A can?
// It only ever sends read-only GETs, only compares status/length/marker presence,
// and never reads or dumps an object's contents.

// runCompare issues the same GET under two header sets. The marker is the caller's
// unique string (an order id, a username): if it appears on both sides, the
// second identity could read the first's object.
func runCompare(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	marker := argRawString(args, "marker")
	headersA := argStringMap(args, "headers_a")
	headersB := argStringMap(args, "headers_b")

	a, err := do(ctx, env, discipline.Request{
		Method: "GET", URL: rawURL, Headers: headersA,
		Purpose: "compare:a", FollowRedirects: true,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: compare (A): %w", err)
	}
	bRes, err := do(ctx, env, discipline.Request{
		Method: "GET", URL: rawURL, Headers: headersB,
		Purpose: "compare:b", FollowRedirects: true,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: compare (B): %w", err)
	}

	b := newObs()
	b.requestID(a.RequestID)
	b.requestID(bRes.RequestID)

	similarity := jaccardText(a.Text(), bRes.Text())
	markerA := marker != "" && strings.Contains(a.Text(), marker)
	markerB := marker != "" && strings.Contains(bRes.Text(), marker)
	verdict := compareVerdict(a, bRes, similarity, marker, markerA, markerB)

	verdictEvidence := map[string]any{
		"request_id": a.RequestID,
		"url":        rawURL,
		"status_a":   a.Status,
		"status_b":   bRes.Status,
		"length_a":   a.BodyBytes,
		"length_b":   bRes.BodyBytes,
		"similarity": math.Round(similarity*10000) / 10000,
		"verdict":    verdict,
	}
	if marker != "" {
		verdictEvidence["marker"] = marker
		verdictEvidence["marker_in_a"] = markerA
		verdictEvidence["marker_in_b"] = markerB
	}
	b.fact(fmt.Sprintf("双账号比对 %s -> %s", rawURL, verdict), verdictEvidence, "compare", verdict)

	if markerA && markerB {
		evidence := map[string]any{
			"request_id": bRes.RequestID,
			"request_a":  a.RequestID,
			"url":        rawURL,
			"status":     bRes.Status,
			"marker":     marker,
		}
		b.fact(fmt.Sprintf("越权候选:%s 标记在两账号均可见", rawURL), evidence, "bola", "idor")
		b.finding(ledger.FindingSeed{
			Title:    "双账号可见同一标记(BOLA/IDOR 候选)",
			Severity: "medium",
			Kind:     "bola",
			Where:    rawURL,
			Detail: fmt.Sprintf("标记 %s 在 A、B 两侧响应中都出现(相似度 %.2f);若 A 是资源所有者、B 是另一个账号,"+
				"则 B 能读到 A 的对象。需用真实测试账号人工复核。", marker, similarity),
			Evidence: evidence,
			Tags:     []string{"bola", "idor"},
		})
	}

	b.setSummary(fmt.Sprintf("compare %s -> %s", rawURL, verdict))
	return b.obs, nil
}

func compareVerdict(a, b *discipline.Response, similarity float64, marker string, markerA, markerB bool) string {
	switch {
	case marker != "" && markerA && markerB:
		return "marker-in-both"
	case marker != "" && markerB && !markerA:
		return "marker-only-in-b"
	case marker != "" && markerA && !markerB:
		return "marker-only-in-a"
	case a.Status != b.Status:
		return "status-diff"
	case similarity < 0.9:
		return "body-diff"
	default:
		return "same"
	}
}
