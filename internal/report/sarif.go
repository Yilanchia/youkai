package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SARIF 2.1.0 export.
//
// The value of SARIF here is not "look, a standard": it is that a CI job or a code
// scanning dashboard can take the ledger's findings without youkai narrating them.
// So each result is anchored to a real location (a URL for web work, file:line for
// binary work) and carries the four evidence pieces in `properties` - the same four
// the report demands, so an integrator cannot accidentally lose them.

// sarifVersion is the only version this export emits.
const sarifVersion = "2.1.0"

// SARIFDocument is the subset of SARIF 2.1.0 youkai produces.
type SARIFDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is one tool invocation.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
	// Properties carries the engagement + coverage so a dashboard can show the
	// boundary the run happened in.
	Properties map[string]any `json:"properties,omitempty"`
}

// SARIFTool describes youkai.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the tool identity + rule catalogue.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule is one finding class.
type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	Help             SARIFMessage   `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

// SARIFMessage is SARIF's {text} object.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult is one finding.
type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Locations  []SARIFLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

// SARIFLocation is where the result was observed.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation is a file (or URI) and a region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation is a URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a 1-based span; SARIF requires a start line.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// SARIFLogicalLocation names a non-file location (a parameter, an endpoint).
type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	Kind               string `json:"kind,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

// fileLine matches "path/to/file:12" (the binary capabilities' Where format).
var fileLine = regexp.MustCompile(`^(.+?):(\d+)(?::\d+)?$`)

// SARIF renders the bundle as a SARIF 2.1.0 document.
func SARIF(b Bundle) ([]byte, error) {
	rules := map[string]SARIFRule{}
	var results []SARIFResult

	for _, f := range b.Findings {
		ruleID := ruleIDFor(f)
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = SARIFRule{
				ID:               ruleID,
				Name:             ruleName(f),
				ShortDescription: SARIFMessage{Text: shortRuleText(f)},
				Help:             SARIFMessage{Text: firstNonEmpty(f.Counter, f.Detail, "youkai 候选发现")},
				Properties: map[string]any{
					"kind":     f.Kind,
					"severity": f.Severity,
				},
			}
		}
		level := "warning"
		if f.State == "verified" {
			level = "error"
		}
		results = append(results, SARIFResult{
			RuleID:    ruleID,
			Level:     level,
			Message:   SARIFMessage{Text: f.Title},
			Locations: locationsFor(f),
			Properties: map[string]any{
				"state":          f.State,
				"severity":       f.Severity,
				"kind":           f.Kind,
				"request_ids":    f.Evidence.RequestIDs,
				"evidence_ok":    f.Evidence.Complete,
				"min_impact":     f.MinImpact,
				"stop_condition": f.StopCondition,
				"counter":        f.Counter,
				"incomplete":     f.Incomplete,
				"disclosable":    f.Disclosable,
				"capability":     f.Capability,
				"engagement":     b.Engagement,
			},
		})
	}

	ruleList := make([]SARIFRule, 0, len(rules))
	for _, id := range sortedRuleIDs(rules) {
		ruleList = append(ruleList, rules[id])
	}

	doc := SARIFDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name: "youkai", Version: Version, InformationURI: "https://github.com/youkai/youkai",
				Rules: ruleList,
			}},
			Results: results,
			Properties: map[string]any{
				"engagement":       b.Engagement,
				"generated_at":     b.GeneratedAt,
				"coverage":         b.Coverage.Statement,
				"hosts":            b.Coverage.Hosts,
				"endpoints":        b.Coverage.Endpoints,
				"incomplete_count": len(b.Incomplete),
			},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// Version is the tool version reported in SARIF; kept in sync with the API version.
const Version = "0.5.0"

func ruleIDFor(f FindingReport) string {
	kind := strings.TrimSpace(f.Kind)
	if kind == "" {
		kind = "unknown"
	}
	return "youkai/" + sanitiseRule(kind)
}

func ruleName(f FindingReport) string {
	if f.Kind == "" {
		return "youkai-finding"
	}
	return "youkai-" + sanitiseRule(f.Kind)
}

func shortRuleText(f FindingReport) string {
	if f.Kind == "" {
		return "youkai 发现"
	}
	return "youkai " + f.Kind + " 发现"
}

// sanitiseRule keeps rule ids to [A-Za-z0-9-._] as SARIF requires.
func sanitiseRule(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

// locationsFor anchors a finding: a URL for web work, file:line for binary work.
func locationsFor(f FindingReport) []SARIFLocation {
	where := strings.TrimSpace(f.Where)
	if where == "" {
		// Fall back to the first cited request's URL, then to the engagement.
		for _, a := range f.Evidence.Audit {
			where = a.URL
			break
		}
	}
	if where == "" {
		return []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: "youkai://engagement"},
				Region:           SARIFRegion{StartLine: 1},
			},
		}}
	}
	if u, err := url.Parse(where); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		logical := []SARIFLogicalLocation{{Name: where, Kind: "url", FullyQualifiedName: where}}
		if param := paramOf(where); param != "" {
			logical = append(logical, SARIFLogicalLocation{Name: "param:" + param, Kind: "parameter"})
		}
		return []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: where},
				Region:           SARIFRegion{StartLine: 1},
			},
			LogicalLocations: logical,
		}}
	}
	if m := fileLine.FindStringSubmatch(where); m != nil {
		line, _ := strconv.Atoi(m[2])
		if line <= 0 {
			line = 1
		}
		return []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: m[1]},
				Region:           SARIFRegion{StartLine: line},
			},
		}}
	}
	return []SARIFLocation{{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: where},
			Region:           SARIFRegion{StartLine: 1},
		},
	}}
}

// paramOf extracts the first query parameter name, for the logical location.
func paramOf(rawURL string) string {
	i := strings.IndexByte(rawURL, '?')
	if i < 0 {
		return ""
	}
	q := rawURL[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	if k := strings.IndexByte(q, '&'); k >= 0 {
		q = q[:k]
	}
	if k := strings.IndexByte(q, '='); k > 0 {
		return q[:k]
	}
	return q
}

func sortedRuleIDs(rules map[string]SARIFRule) []string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	// Deterministic order: SARIF consumers may diff runs.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ = fmt.Sprintf
