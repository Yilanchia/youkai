package binary

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"youkai/internal/ledger"
)

var (
	urlSampleRe     = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\\]{4,}`)
	winPathSampleRe = regexp.MustCompile(`[A-Za-z]:\\[^\s"'<>|]{3,}`)
	nixPathSampleRe = regexp.MustCompile(`/(?:usr|etc|home|root|var|opt|bin|sbin|lib|lib64|tmp|data|system|proc|dev|srv)/[^\s"'<>]{2,}`)
	libSampleRe     = regexp.MustCompile(`(?i)[\w.\-]+\.(?:dll|so(?:\.\d+)*|dylib|exe|sys)\b`)
	stringKeywordRe = regexp.MustCompile(`(?i)password|passwd|api[_-]?key|apikey|secret|token|BEGIN |PRIVATE KEY|https?://|\.dll\b|\.so\b|C:\\`)
	// longSecretBlobRe masks long base64-ish runs (PEM bodies, raw key material)
	// even when they are not preceded by a provider keyword.
	longSecretBlobRe = regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}\b`)
)

const (
	maxRawStrings        = 50000
	sampleMaxLen         = 200
	maxStoredStringBytes = 4096
)

type rawString struct {
	Value  string
	Offset int
}

// stringsCapability extracts bounded printable strings and reports counts plus
// redacted samples. It never returns the raw credential-shaped values.
func stringsCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	minLength := clampInt(argInt(args, "min_length", 5), 3, 64)
	limit := clampInt(argInt(args, "limit", 400), 1, 1000)

	data, err := os.ReadFile(path)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 读取 %s: %v", ErrRefused, path, err)
	}
	if int64(len(data)) != size {
		return ledger.Observation{}, fmt.Errorf("%w: 读取大小与文件信息不一致,文件可能被修改", ErrRefused)
	}

	ascii, utf16 := extractStrings(data, minLength, maxRawStrings, ctx)
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}

	counts := struct {
		urls     int
		paths    int
		keywords int
	}{}
	type candidate struct {
		offset int
		kind   string
		value  string
	}
	// Priority order: credential-ish keywords first, then URLs, then paths.
	byPriority := make([][]candidate, 3)
	for _, list := range [][]rawString{ascii, utf16} {
		for _, s := range list {
			classes := classifyString(s.Value)
			if containsString(classes, "keyword") {
				counts.keywords++
				byPriority[0] = append(byPriority[0], candidate{s.Offset, "keyword", s.Value})
			}
			if containsString(classes, "url") {
				counts.urls++
				byPriority[1] = append(byPriority[1], candidate{s.Offset, "url", s.Value})
			}
			if containsString(classes, "path") {
				counts.paths++
				byPriority[2] = append(byPriority[2], candidate{s.Offset, "path", s.Value})
			}
		}
	}
	samples := make([]map[string]any, 0, limit)
	for _, bucket := range byPriority {
		for _, cand := range bucket {
			if len(samples) >= limit {
				break
			}
			samples = append(samples, map[string]any{
				"offset": cand.offset,
				"kind":   cand.kind,
				"sample": sanitizeStringSample(cand.value),
			})
		}
	}

	total := len(ascii) + len(utf16)
	statement := fmt.Sprintf(
		"strings: %s 提取可打印字符串 %d 条(ascii=%d utf16le=%d),命中 url=%d path=%d keyword=%d,采样 %d 条(已脱敏)",
		path, total, len(ascii), len(utf16), counts.urls, counts.paths, counts.keywords, len(samples))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":            path,
		"total":           total,
		"ascii_count":     len(ascii),
		"utf16le_count":   len(utf16),
		"url_count":       counts.urls,
		"path_count":      counts.paths,
		"keyword_count":   counts.keywords,
		"min_length":      minLength,
		"limit":           limit,
		"samples":         samples,
		"redacted":        true,
		"truncated":       total >= maxRawStrings,
		"source":          "native-string-extractor",
		"executed_sample": false,
	})
	return ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "strings", "tier1"}, []string{"artifact:" + path})},
		Summary: statement,
	}, nil
}

// extractStrings walks the buffer once for ASCII runs and once for UTF-16LE
// runs. Both are capped so a pathological file cannot blow up memory or time.
func extractStrings(data []byte, minLength, maxRaw int, ctx context.Context) (ascii, utf16 []rawString) {
	for i := 0; i < len(data) && len(ascii) < maxRaw; {
		if i%65536 == 0 {
			if ctx.Err() != nil {
				return ascii, utf16
			}
		}
		if !isPrintableASCII(data[i]) {
			i++
			continue
		}
		start := i
		for i < len(data) && isPrintableASCII(data[i]) {
			i++
		}
		if i-start >= minLength {
			value := string(data[start:i])
			if len(value) > maxStoredStringBytes {
				value = value[:maxStoredStringBytes]
			}
			ascii = append(ascii, rawString{Value: value, Offset: start})
		}
	}

	for i := 0; i+1 < len(data) && len(utf16) < maxRaw; {
		if i%65536 == 0 {
			if ctx.Err() != nil {
				return ascii, utf16
			}
		}
		if !isPrintableASCII(data[i]) || data[i+1] != 0x00 {
			i++
			continue
		}
		start := i
		var sb strings.Builder
		for i+1 < len(data) && isPrintableASCII(data[i]) && data[i+1] == 0x00 {
			sb.WriteByte(data[i])
			i += 2
		}
		if sb.Len() >= minLength {
			value := sb.String()
			if len(value) > maxStoredStringBytes {
				value = value[:maxStoredStringBytes]
			}
			utf16 = append(utf16, rawString{Value: value, Offset: start})
		}
	}
	return ascii, utf16
}

func isPrintableASCII(b byte) bool { return b >= 0x20 && b <= 0x7e }

func classifyString(s string) []string {
	var classes []string
	if urlSampleRe.MatchString(s) {
		classes = append(classes, "url")
	}
	if winPathSampleRe.MatchString(s) || nixPathSampleRe.MatchString(s) || libSampleRe.MatchString(s) {
		classes = append(classes, "path")
	}
	if stringKeywordRe.MatchString(s) {
		classes = append(classes, "keyword")
	}
	return classes
}

// sanitizeStringSample truncates, scrubs provider secrets, and strips URL
// query/userinfo before a sample can reach the ledger.
func sanitizeStringSample(s string) string {
	s = clipString(s, sampleMaxLen)
	s = redactTokens(s)
	s = longSecretBlobRe.ReplaceAllStringFunc(s, maskedPreview)
	return urlSampleRe.ReplaceAllStringFunc(s, redactURLSample)
}

func redactURLSample(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return clipString(raw, 48)
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" {
		u.RawQuery = "<redacted>"
	}
	return u.String()
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
