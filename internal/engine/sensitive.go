package engine

import (
	"regexp"
	"strings"
)

// SensitiveHit names a secret-like pattern found in a capability's output.
//
// Why this stops the whole run rather than one step: a target that leaks
// credentials changes the engagement's risk profile. The right next move is a
// human deciding what to do with it, not the engine continuing to roam.
type SensitiveHit struct {
	// Name is a stable label, e.g. "private-key".
	Name string `json:"name"`
	// Note is a short, non-secret description of where it matched.
	Note string `json:"note"`
}

var sensitivePatterns = []struct {
	name string
	note string
	re   *regexp.Regexp
}{
	{"private-key", "PEM private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"aws-access-key", "AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"github-token", "GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"slack-token", "Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"jwt", "JSON web token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.`)},
	{"openai-key", "sk-style secret key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`)},
	{"password-literal", "literal password assignment", regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*["'][^\s"']{6,}`)},
	{"basic-auth-url", "credentials embedded in a URL", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`)},
}

// ScanSensitive finds secret-like material in text a capability produced.
func ScanSensitive(text string) (SensitiveHit, bool) {
	if strings.TrimSpace(text) == "" {
		return SensitiveHit{}, false
	}
	for _, p := range sensitivePatterns {
		if loc := p.re.FindStringIndex(text); loc != nil {
			// Never copy the match into the record: a sensitive hit must not
			// become the leak it reports.
			return SensitiveHit{
				Name: p.name,
				Note: p.note + " (offset " + itoa(loc[0]) + ")",
			}, true
		}
	}
	return SensitiveHit{}, false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
