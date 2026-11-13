package result

import "testing"

func TestRequestIDShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"probe", `{"request_id":"R0001","url":"http://x","status":200}`, "R0001"},
		{"compare a/b", `{"verdict":"same","a":{"request_id":"RA"},"b":{"request_id":"RB"}}`, "RA"},
		{"nested result", `{"result":{"request_id":"RN"}}`, "RN"},
		{"param findings only", `{"targets":["http://x"],"findings":[{"kind":"sqli","evidence":{"request_id":"RF"}}]}`, "RF"},
		{"requests array", `{"requests":[{"request_id":"RQ"}]}`, "RQ"},
		{"nothing", `{"ok":true}`, ""},
		{"not json", `plain text`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RequestID(c.text); got != c.want {
				t.Fatalf("RequestID = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRequestIDsCollects(t *testing.T) {
	text := `{"request_id":"R1","findings":[{"evidence":{"request_id":"R2"}},{"evidence":{"request_id":"R1"}}],"a":{"request_id":"R3"}}`
	got := RequestIDs(text, 0)
	want := []string{"R1", "R2", "R3"}
	if len(got) != len(want) {
		t.Fatalf("RequestIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RequestIDs = %v, want %v", got, want)
		}
	}
}

func TestURLAndSummary(t *testing.T) {
	if got := URL(`{"final_url":"http://x/y"}`); got != "http://x/y" {
		t.Fatalf("URL = %q", got)
	}
	sum := Summary(`{"url":"http://x","status":200,"findings":[{},{}]}`)
	if sum != "url=http://x status=200 findings=2" {
		t.Fatalf("Summary = %q", sum)
	}
}
