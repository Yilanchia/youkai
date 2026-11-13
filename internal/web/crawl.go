package web

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// Same-origin breadth-first crawl.
//
// Bounds are the point: a crawl that can spend unbounded requests is not a
// capability, it is a liability. max_pages defaults to 20 and cannot exceed 40;
// max_depth defaults to 2 and cannot exceed 5. Every URL is requested at most
// once, and only URLs whose origin equals the seed's are ever queued.

const (
	defaultCrawlPages = 20
	maxCrawlPages     = 40
	defaultCrawlDepth = 2
	maxCrawlDepth     = 5
	maxLinksPerPage   = 400
)

var linkRx = regexp.MustCompile(`(?is)\b(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))`)

type crawlItem struct {
	url   string
	depth int
}

func runCrawl(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	seed, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	seedURL := normalizeLink(seed, seed)
	if seedURL == "" {
		return ledger.Observation{}, fmt.Errorf("web: crawl: %q is not an absolute http(s) URL", seed)
	}
	maxPages := clamp(argInt(args, "max_pages", defaultCrawlPages), 1, maxCrawlPages)
	maxDepth := clamp(argInt(args, "max_depth", defaultCrawlDepth), 0, maxCrawlDepth)
	headers := argStringMap(args, "headers")
	seedOrigin := originOf(seedURL)

	b := newObs()
	visited := map[string]bool{}
	queued := map[string]bool{seedURL: true}
	discovered := map[string]bool{}
	queue := []crawlItem{{url: seedURL, depth: 0}}

	// addEndpoint emits the one fact and one asset a discovered URL gets. The
	// request_id is the audited page that proved the URL exists (the page that
	// linked to it, or the URL's own response for the seed).
	addEndpoint := func(endpoint, requestID string) {
		if discovered[endpoint] {
			return
		}
		discovered[endpoint] = true
		b.fact("发现端点:"+endpoint, map[string]any{
			"request_id": requestID,
			"url":        endpoint,
		}, "crawl")
		b.asset("endpoint", "endpoint:"+endpoint)
	}

	pages := 0
	attempts := 0
	var firstErr error
	// attempts counts every guarded request, successful or not, so a page full of
	// failing links cannot push the crawl past its page budget.
	for len(queue) > 0 && attempts < maxPages {
		item := queue[0]
		queue = queue[1:]
		if visited[item.url] {
			continue
		}
		visited[item.url] = true
		attempts++

		res, err := do(ctx, env, discipline.Request{
			Method:          "GET",
			URL:             item.url,
			Headers:         headers,
			Purpose:         "crawl",
			FollowRedirects: true,
		})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if fatalCrawlErr(err) {
				break
			}
			continue
		}
		pages++
		b.requestID(res.RequestID)
		addEndpoint(item.url, res.RequestID)

		if item.depth >= maxDepth || res.Status >= 400 || !looksLikeHTML(res) {
			continue
		}
		for _, link := range extractLinks(res.Text(), item.url, seedOrigin) {
			if visited[link] || queued[link] {
				continue
			}
			// Record every discovered endpoint, even when the page budget will
			// not let us fetch it: the page that names it is the evidence.
			addEndpoint(link, res.RequestID)
			if len(queue) >= maxPages {
				continue
			}
			queued[link] = true
			queue = append(queue, crawlItem{url: link, depth: item.depth + 1})
		}
	}

	if pages == 0 {
		if firstErr != nil {
			return ledger.Observation{}, fmt.Errorf("web: crawl: %w", firstErr)
		}
		return ledger.Observation{}, fmt.Errorf("web: crawl: no page could be fetched within the bounds")
	}
	b.setSummary(fmt.Sprintf("crawl %s: %d 页, 发现 %d 端点", seedURL, pages, len(discovered)))
	return b.obs, nil
}

// fatalCrawlErr reports whether continuing the crawl would just audit more
// refusals: an exhausted budget or a scope refusal is a stop, not a skip.
func fatalCrawlErr(err error) bool {
	return errors.Is(err, discipline.ErrRequestBudget) ||
		errors.Is(err, discipline.ErrOutOfScope) ||
		errors.Is(err, discipline.ErrMethodNotAllowed) ||
		errors.Is(err, discipline.ErrNoScope) ||
		errors.Is(err, discipline.ErrExpired) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// looksLikeHTML keeps link extraction off JSON and binary responses while still
// tolerating a server that mislabels its Content-Type.
func looksLikeHTML(res *discipline.Response) bool {
	if isHTMLResponse(res) {
		return true
	}
	head := strings.ToLower(res.Snippet(512))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html") ||
		strings.Contains(head, "<a ") || strings.Contains(head, "<form")
}

// extractLinks pulls href/src/action values, resolves them against the page, and
// keeps only same-origin http(s) URLs with the fragment removed.
func extractLinks(body, pageURL, wantOrigin string) []string {
	if body == "" {
		return nil
	}
	matches := linkRx.FindAllStringSubmatch(body, maxLinksPerPage)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range matches {
		raw := ""
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				raw = m[i]
				break
			}
		}
		link := normalizeLink(raw, pageURL)
		if link == "" || seen[link] {
			continue
		}
		if originOf(link) != wantOrigin {
			continue
		}
		seen[link] = true
		out = append(out, link)
	}
	return out
}
