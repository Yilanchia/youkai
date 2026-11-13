package binary

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"youkai/internal/ledger"
)

// sarifInput is the only input shape this capability accepts. It deliberately
// does not read the ledger: the caller passes the findings in.
type sarifInput struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Where    string `json:"where"`
	Detail   string `json:"detail"`
}

// SARIF 2.1.0 document types, kept minimal and valid.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifMessage   `json:"shortDescription"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

var sarifLineRe = regexp.MustCompile(`^(.*?):(\d+)$`)
var sarifAddrRe = regexp.MustCompile(`^(.*):0x[0-9a-fA-F]+$`)

// sarifCapability converts a JSON findings array into a minimal SARIF 2.1.0
// file under ArtifactDir. The document stays on disk; only its path and counts
// become a fact.
func sarifCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	findings, err := loadSARIFInput(args)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	engagement := argString(args, "engagement")
	if engagement == "" {
		engagement = env.Engagement
	}

	rules := make([]sarifRule, 0, 8)
	ruleIndex := map[string]int{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		kind := strings.TrimSpace(f.Kind)
		if kind == "" {
			kind = "finding"
		}
		ruleID := "youkai/" + kind
		idx, ok := ruleIndex[ruleID]
		if !ok {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			title := f.Title
			if title == "" {
				title = kind
			}
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             kind,
				ShortDescription: sarifMessage{Text: clipString(title, 200)},
				DefaultConfiguration: map[string]any{
					"level": sarifLevel(f.Severity),
				},
			})
		}
		uri, line := splitSARIFWhere(f.Where)
		message := f.Title
		if message == "" {
			message = kind
		}
		if f.Detail != "" {
			message += " — " + f.Detail
		}
		results = append(results, sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: clipString(message, 1000)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
					Region:           sarifRegion{StartLine: line},
				},
			}},
			Properties: map[string]any{
				"kind":                kind,
				"severity":            ledger.NormaliseSeverity(f.Severity),
				"where":               f.Where,
				"epistemic":           "inferred",
				"generated_by":        "youkai internal/binary sarif",
				"candidate_not_proof": true,
			},
		})
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "youkai",
				Version:        "0.2.0",
				InformationURI: "https://github.com/",
				Rules:          rules,
			}},
			Results: results,
			Properties: map[string]any{
				"engagement": engagement,
				"note":       "所有 result 都是待人工复核的静态候选,不是已验证漏洞。",
			},
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 编码 SARIF: %v", ErrRefused, err)
	}
	data = append(data, '\n')
	outPath, err := writeArtifact(env, "report.sarif", data)
	if err != nil {
		return ledger.Observation{}, err
	}

	statement := fmt.Sprintf("sarif: 已生成 SARIF 2.1.0: %s(%d 条结果,%d 条规则)", outPath, len(results), len(rules))
	evidence := evidenceWithLocation(outPath, map[string]any{
		"path":       outPath,
		"format":     "SARIF 2.1.0",
		"results":    len(results),
		"rules":      len(rules),
		"engagement": engagement,
		"bytes":      len(data),
		"source":     "native-json-transform",
		"note":       "文档仅落盘,不进入账本证据;内容为静态候选,epistemic=inferred",
	})
	return ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "sarif", "report", "tier1"}, nil)},
		Summary: statement,
	}, nil
}

// loadSARIFInput accepts findings inline (array or JSON string) or a JSON file
// path. A file may hold an array or an object with a "findings" array.
func loadSARIFInput(args map[string]any) ([]sarifInput, error) {
	if args != nil {
		if raw, ok := args["findings"]; ok {
			switch v := raw.(type) {
			case []sarifInput:
				return v, nil
			case []map[string]any:
				return convertSARIFMaps(v)
			case []any:
				maps := make([]map[string]any, 0, len(v))
				for _, item := range v {
					if m, ok := item.(map[string]any); ok {
						maps = append(maps, m)
					}
				}
				return convertSARIFMaps(maps)
			case string:
				return decodeSARIFBytes([]byte(v))
			}
		}
	}
	if path := argString(args, "path"); path != "" {
		abs, _, err := inputFilePath(path, true)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, fmt.Errorf("%w: 读取 findings 文件 %s: %v", ErrRefused, abs, err)
		}
		return decodeSARIFBytes(data)
	}
	return nil, fmt.Errorf("%w: sarif 需要 args.findings(JSON 数组)或 args.path(JSON 文件)", ErrRefused)
}

func decodeSARIFBytes(data []byte) ([]sarifInput, error) {
	var arr []sarifInput
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	var wrapper struct {
		Findings []sarifInput `json:"findings"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Findings != nil {
		return wrapper.Findings, nil
	}
	var loose []map[string]any
	if err := json.Unmarshal(data, &loose); err != nil {
		return nil, fmt.Errorf("%w: findings JSON 既不是数组也不是含 findings 数组的对象", ErrRefused)
	}
	return convertSARIFMaps(loose)
}

func convertSARIFMaps(maps []map[string]any) ([]sarifInput, error) {
	out := make([]sarifInput, 0, len(maps))
	for _, m := range maps {
		out = append(out, sarifInput{
			Title:    mapString(m, "title"),
			Severity: mapString(m, "severity"),
			Kind:     mapString(m, "kind"),
			Where:    mapString(m, "where"),
			Detail:   mapString(m, "detail"),
		})
	}
	return out, nil
}

func mapString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func sarifLevel(severity string) string {
	switch ledger.NormaliseSeverity(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// splitSARIFWhere turns "src/x.c:12" or "<path>:0x401000" into a URI and a
// start line (1 when only an offset is known).
func splitSARIFWhere(where string) (string, int) {
	trimmed := strings.TrimSpace(where)
	if trimmed == "" {
		return "<unknown>", 1
	}
	if m := sarifLineRe.FindStringSubmatch(trimmed); m != nil {
		if n, err := strconv.Atoi(m[2]); err == nil && n > 0 {
			return filepath.ToSlash(m[1]), n
		}
	}
	if m := sarifAddrRe.FindStringSubmatch(trimmed); m != nil {
		return filepath.ToSlash(m[1]), 1
	}
	return filepath.ToSlash(trimmed), 1
}
