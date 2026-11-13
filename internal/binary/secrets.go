package binary

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"youkai/internal/ledger"
)

// secretRule is one provider signature or heuristic. Group selects the capture
// that is the secret value when the match includes surrounding context.
type secretRule struct {
	ID         string
	Class      string
	Severity   string
	Note       string
	Re         *regexp.Regexp
	Group      int
	MinEntropy float64
}

// secretRules mirror the provider signatures Verdex used, plus connection
// strings and password assignments. Read-only, no validation, no network.
var secretRules = []secretRule{
	{
		ID: "aws-access-key-id", Class: "aws-access-key-id", Severity: "high",
		Note: "AWS Access Key ID", Group: 0,
		Re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		ID: "aws-secret-access-key", Class: "aws-secret-access-key", Severity: "high",
		Note: "AWS Secret Access Key", Group: 1,
		Re: regexp.MustCompile(`(?i)\baws_secret_access_key\b["'\s:=]+([A-Za-z0-9/+]{40})\b`),
	},
	{
		ID: "github-token", Class: "github-token", Severity: "high",
		Note: "GitHub Token", Group: 0,
		Re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
	},
	{
		ID: "github-fine-grained", Class: "github-fine-grained", Severity: "high",
		Note: "GitHub fine-grained PAT", Group: 0,
		Re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`),
	},
	{
		ID: "google-api-key", Class: "google-api-key", Severity: "medium",
		Note: "Google API Key", Group: 0,
		Re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		ID: "slack-token", Class: "slack-token", Severity: "high",
		Note: "Slack Token", Group: 0,
		Re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`),
	},
	{
		ID: "stripe-secret", Class: "stripe-secret", Severity: "critical",
		Note: "Stripe Live Secret Key", Group: 0,
		Re: regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`),
	},
	{
		ID: "stripe-restricted", Class: "stripe-restricted", Severity: "high",
		Note: "Stripe Restricted Key", Group: 0,
		Re: regexp.MustCompile(`\brk_live_[0-9A-Za-z]{24,}\b`),
	},
	{
		ID: "private-key", Class: "private-key", Severity: "critical",
		Note: "私钥(PEM)", Group: 0,
		Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		ID: "jwt", Class: "jwt", Severity: "medium",
		Note: "JWT(危害取决于是否有效/高权)", Group: 0,
		Re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
	},
	{
		ID: "slack-webhook", Class: "slack-webhook", Severity: "high",
		Note: "Slack Webhook URL", Group: 0,
		Re: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`),
	},
	{
		ID: "connection-string", Class: "connection-string", Severity: "medium",
		Note: "数据库/消息队列连接串(可能含口令)", Group: 0,
		Re: regexp.MustCompile(`(?i)\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql|jdbc:[a-z]+|ftp)://[^\s"'<>]{6,}`),
	},
	{
		ID: "password-assignment", Class: "password-assignment", Severity: "medium",
		Note: "口令赋值", Group: 1,
		Re: regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"'&,;]{6,})["']?`),
	},
	{
		ID: "named-secret-constant", Class: "named-secret-constant", Severity: "medium",
		Note: "命名凭据常量赋值", Group: 1,
		Re: regexp.MustCompile(`(?i)\b[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|APPKEY|APPSECRET)\b\s*[:=]\s*["']?([^\s"'&,;]{6,})["']?`),
	},
	{
		ID: "generic-assignment", Class: "generic-assignment", Severity: "medium",
		Note: "通用密钥赋值(高熵)", Group: 1, MinEntropy: 3.5,
		Re: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9/+_\-]{16,})["']?`),
	},
}

// credentialAssignRe is the last-resort scrub used when strings samples could
// otherwise echo a credential assignment verbatim. The key part may be a
// compound identifier such as DB_PASSWORD.
var credentialAssignRe = regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key))\b\s*[:=]\s*[^\s"',;]{3,}`)

// maskedPreview keeps at most the first four characters, per the package's
// "never echo a secret" rule.
func maskedPreview(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "…"
}

// redactTokens scrubs every known secret shape out of an arbitrary string
// before it can reach a fact or finding.
func redactTokens(s string) string {
	for _, rule := range secretRules {
		s = rule.Re.ReplaceAllStringFunc(s, func(m string) string {
			if rule.Group > 0 {
				idx := rule.Re.FindStringSubmatchIndex(m)
				if len(idx) >= 2*(rule.Group+1) && idx[2*rule.Group] >= 0 {
					start, end := idx[2*rule.Group], idx[2*rule.Group+1]
					return m[:start] + maskedPreview(m[start:end]) + m[end:]
				}
			}
			return maskedPreview(m)
		})
	}
	return credentialAssignRe.ReplaceAllString(s, "${1}=<redacted>")
}

// secretHit is one redacted detection, ready to become a finding.
type secretHit struct {
	RuleID   string
	Class    string
	Severity string
	Note     string
	Path     string
	Offset   int64
	Line     int
	Column   int
	Preview  string
	ValueLen int
	ValueSHA string
}

const maxSecretHits = 200

// scanSecretsBytes applies every rule to one buffer. It never stores or
// returns the matched value: only its masked preview, length, and a digest.
func scanSecretsBytes(ctx context.Context, path string, data []byte, seen map[string]bool, hits *[]secretHit) error {
	for _, rule := range secretRules {
		if len(*hits) >= maxSecretHits {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		matches := rule.Re.FindAllSubmatchIndex(data, maxSecretHits)
		for _, m := range matches {
			if len(*hits) >= maxSecretHits {
				return nil
			}
			start, end := m[0], m[1]
			if rule.Group > 0 {
				if len(m) < 2*(rule.Group+1) {
					continue
				}
				start, end = m[2*rule.Group], m[2*rule.Group+1]
				if start < 0 || end < 0 {
					continue
				}
			}
			value := string(data[start:end])
			if looksLikePlaceholder(value) {
				continue
			}
			if rule.MinEntropy > 0 && shannonEntropy(value) < rule.MinEntropy {
				continue
			}
			key := fmt.Sprintf("%s|%s|%d", rule.ID, path, start)
			if seen[key] {
				continue
			}
			seen[key] = true
			line, column := lineColumnAt(data, start)
			*hits = append(*hits, secretHit{
				RuleID:   rule.ID,
				Class:    rule.Class,
				Severity: rule.Severity,
				Note:     rule.Note,
				Path:     path,
				Offset:   int64(start),
				Line:     line,
				Column:   column,
				Preview:  maskedPreview(value),
				ValueLen: len(value),
				ValueSHA: sha256Bytes([]byte(value))[:16],
			})
		}
	}
	return nil
}

// looksLikePlaceholder filters obvious template values without hiding real
// provider-shaped keys: real keys never contain angle brackets or YOUR_.
func looksLikePlaceholder(value string) bool {
	lower := strings.ToLower(value)
	if strings.ContainsAny(value, "<>") {
		return true
	}
	for _, marker := range []string{"your_", "your-", "replace_me", "changeme", "xxxxxxx"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func lineColumnAt(data []byte, offset int) (line, column int) {
	if offset > len(data) {
		offset = len(data)
	}
	line = 1 + bytes.Count(data[:offset], []byte("\n"))
	lastNewline := bytes.LastIndexByte(data[:offset], '\n')
	return line, offset - lastNewline
}

// secretsCapability scans one file (path) or a directory tree (path or dir).
func secretsCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	raw := argString(args, "path")
	if raw == "" {
		raw = argString(args, "dir")
	}
	root, info, err := inputPathAllowDir(raw)
	if err != nil {
		return ledger.Observation{}, err
	}

	var (
		hits         []secretHit
		seen         = map[string]bool{}
		scannedFiles int
		skipped      []string
		totalBytes   int64
	)
	if info.IsDir() {
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.IsDir() {
				if skipScanDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if scannedFiles >= maxDirFiles || len(hits) >= maxSecretHits {
				return filepath.SkipAll
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			if !fi.Mode().IsRegular() {
				return nil
			}
			if fi.Size() > maxDirFileSize || totalBytes+fi.Size() > maxDirBytes {
				skipped = append(skipped, p+" (超单文件/总量上限,未扫描)")
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			if looksBinary(data) && !isTextExtension(filepath.Ext(p)) {
				skipped = append(skipped, p+" (二进制,跳过文本正则)")
				return nil
			}
			totalBytes += int64(len(data))
			scannedFiles++
			return scanSecretsBytes(ctx, p, data, seen, &hits)
		})
		if walkErr != nil {
			return ledger.Observation{}, walkErr
		}
	} else {
		data, err := os.ReadFile(root)
		if err != nil {
			return ledger.Observation{}, fmt.Errorf("%w: 读取 %s: %v", ErrRefused, root, err)
		}
		scannedFiles = 1
		totalBytes = int64(len(data))
		if err := scanSecretsBytes(ctx, root, data, seen, &hits); err != nil {
			return ledger.Observation{}, err
		}
	}

	obs := ledger.Observation{}
	bySeverity := map[string]int{}
	byClass := map[string]int{}
	for _, hit := range hits {
		bySeverity[hit.Severity]++
		byClass[hit.Class]++
	}
	obs.Findings = append(obs.Findings, secretFindings(hits, root)...)

	statement := fmt.Sprintf(
		"secrets: %s 扫描 %d 个文件,命中 %d 处(critical=%d high=%d medium=%d),仅输出脱敏预览、未验证凭据有效性",
		root, scannedFiles, len(hits), bySeverity["critical"], bySeverity["high"], bySeverity["medium"])
	evidence := evidenceWithLocation(root, map[string]any{
		"path":          root,
		"files_scanned": scannedFiles,
		"bytes_scanned": totalBytes,
		"hits":          len(hits),
		"by_severity":   bySeverity,
		"by_class":      byClass,
		"redacted":      true,
		"validated":     false,
		"network":       false,
		"source":        "native-regex-sweep",
		"truncated":     len(hits) >= maxSecretHits,
	})
	if len(skipped) > 0 {
		evidence["skipped"] = clipStrings(skipped, 30)
	}
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "secrets", "tier1"}, []string{"artifact:" + root}))
	obs.Summary = statement
	return obs, nil
}

// secretFindings turns redacted hits into candidate findings. It is shared by
// the secrets capability and by mobile_unpack's post-extraction re-scan, so
// the redaction rules live in exactly one place.
func secretFindings(hits []secretHit, anchor string) []ledger.FindingSeed {
	out := make([]ledger.FindingSeed, 0, len(hits))
	for _, hit := range hits {
		where := fmt.Sprintf("%s:%d", hit.Path, hit.Offset)
		detail := fmt.Sprintf("规则=%s 类=%s 行=%d 列=%d 预览=%s 值长度=%d;值已脱敏,未验证凭据有效性(只读静态正则,不联网)。",
			hit.RuleID, hit.Class, hit.Line, hit.Column, hit.Preview, hit.ValueLen)
		out = append(out, newFinding(
			"硬编码凭据:"+hit.Note+" (值已脱敏)",
			hit.Severity,
			"secret",
			where,
			detail,
			evidenceWithLocation(hit.Path, map[string]any{
				"rule":         hit.RuleID,
				"class":        hit.Class,
				"path":         hit.Path,
				"offset":       hit.Offset,
				"line":         hit.Line,
				"column":       hit.Column,
				"preview":      hit.Preview,
				"value_len":    hit.ValueLen,
				"value_sha256": hit.ValueSHA,
				"redacted":     true,
				"validated":    false,
				"source":       "native-regex-sweep",
			}),
			[]string{"binary", "secrets", "tier1"},
			[]string{"artifact:" + anchor},
		))
	}
	return out
}

// skipScanDir keeps the sweep out of dependency and VCS trees.
func skipScanDir(name string) bool {
	switch name {
	case ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__", ".idea", ".vscode":
		return true
	}
	return false
}

// looksBinary is a cheap NUL-byte heuristic over the first 4 KiB.
func looksBinary(data []byte) bool {
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	return bytes.IndexByte(data[:limit], 0x00) >= 0
}

// isTextExtension reports whether an extension is scanned even if it contains
// NUL bytes (some templates and minified assets do).
func isTextExtension(ext string) bool {
	switch strings.ToLower(ext) {
	case ".c", ".h", ".cc", ".cpp", ".hpp", ".java", ".kt", ".js", ".mjs", ".cjs", ".ts",
		".tsx", ".jsx", ".py", ".rb", ".php", ".go", ".cs", ".rs", ".swift", ".json",
		".xml", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".properties", ".env", ".txt",
		".md", ".sh", ".ps1", ".bat", ".sql", ".html", ".vue", ".gradle", ".toml",
		".pem", ".key", "":
		return true
	}
	return false
}

func clipStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
