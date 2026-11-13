package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

var gitConfigRx = regexp.MustCompile(`\.git/config$`)

// runProbe sends exactly one guarded request and records what came back.
//
// A probe is the smallest unit of evidence youkai has: one request, one audit
// row, one fact. The git-config special case is Fairy's most useful single
// signal, so it gets its own fact shape that downstream playbooks can match on.
func runProbe(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	method := strings.ToUpper(argString(args, "method"))
	if method == "" {
		method = "GET"
	}
	headers := argStringMap(args, "headers")
	res, err := do(ctx, env, discipline.Request{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Purpose:         "probe",
		FollowRedirects: argBool(args, "follow_redirects", true),
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: probe: %w", err)
	}

	b := newObs()
	b.requestID(res.RequestID)
	b.fact(fmt.Sprintf("%s %s -> %d", method, res.URL, res.Status), respEvidence(res))

	if res.Status == 200 {
		gitURL := ""
		switch {
		case gitConfigRx.MatchString(res.URL):
			gitURL = res.URL
		case res.FinalURL != "" && gitConfigRx.MatchString(res.FinalURL):
			gitURL = res.FinalURL
		}
		if gitURL != "" {
			b.fact("git 配置可读:"+gitURL, respEvidence(res), "git", "exposed")
		}
	}
	b.setSummary(fmt.Sprintf("%s %s -> %d", method, res.URL, res.Status))
	return b.obs, nil
}
