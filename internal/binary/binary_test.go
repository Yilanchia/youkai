package binary

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

func testEnv(t *testing.T) *Env {
	t.Helper()
	return &Env{
		ArtifactDir:  filepath.Join(t.TempDir(), "artifacts"),
		EngagementID: 1,
		Engagement:   "unit-test",
	}
}

func observationJSON(t *testing.T, obs ledger.Observation) string {
	t.Helper()
	b, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	return string(b)
}

// ---- registry ---------------------------------------------------------------

func TestRegistryMatchesGateTable(t *testing.T) {
	want := []string{
		"blind_screen",
		"artifact_identify", "artifact_register", "strings", "checksec", "symbols",
		"disasm", "decompile", "mobile_unpack", "firmware_extract", "secrets",
		"dataflow", "sarif", "doctor",
		"pwn_template", "pwn_gdbscript", "impact_proof", "frida_script", "web_poc",
		"download",
	}
	caps := Registry()
	if len(caps) != len(want) {
		t.Fatalf("registry has %d capabilities, want %d", len(caps), len(want))
	}
	for i, name := range want {
		if caps[i].Name != name {
			t.Errorf("registry[%d] = %q, want %q", i, caps[i].Name, name)
		}
		c, ok := Lookup(name)
		if !ok {
			t.Errorf("Lookup(%q) failed", name)
			continue
		}
		if c.Description == "" {
			t.Errorf("%s has empty description", name)
		}
		if tier := gate.Classify(name, nil); tier != c.Tier {
			t.Errorf("%s tier = %v, gate says %v", name, c.Tier, tier)
		}
		if c.Run == nil {
			t.Errorf("%s has nil Run", name)
		}
	}
	if _, ok := Lookup("not_a_capability"); ok {
		t.Error("Lookup accepted an unknown capability")
	}
	if _, err := Run(context.Background(), testEnv(t), "not_a_capability", nil); err == nil {
		t.Error("Run accepted an unknown capability")
	}
}

// ---- identify ---------------------------------------------------------------

func TestIdentifyFormats(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	machO := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0, 0, 0, 0}
	fatMachO := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02}
	fatMachO = append(fatMachO, 0x01, 0x00, 0x00, 0x07)
	fatMachO = append(fatMachO, make([]byte, 20+20)...)

	cases := []struct {
		name       string
		data       []byte
		wantFormat string
		wantArch   string
	}{
		{"sample.elf", buildELF(t, elfSpec{stack: true, relro: true}), "ELF", "amd64"},
		{"sample.exe", buildPE(t, 0x4160), "PE", "amd64"},
		{"sample.apk", buildAPK(t, false), "APK", "dalvik"},
		{"sample.dex", append([]byte("dex\n035\x00"), make([]byte, 16)...), "DEX", "dalvik"},
		{"sample.class", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, "Java class", "jvm"},
		{"sample.wasm", []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, "WebAssembly", "wasm32"},
		{"sample.macho", machO, "Mach-O", "amd64"},
		{"sample.fat", fatMachO, "Mach-O", "fat"},
		{"sample.bin", []byte("this is not a known executable format at all"), "firmware", "unknown"},
		{"sample.squashfs", append([]byte("hsqs"), make([]byte, 64)...), "firmware", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFixture(t, dir, tc.name, tc.data)
			obs, err := Run(context.Background(), env, "artifact_identify", map[string]any{"path": path})
			if err != nil {
				t.Fatalf("identify: %v", err)
			}
			if len(obs.Facts) != 1 {
				t.Fatalf("want 1 fact, got %d", len(obs.Facts))
			}
			statement := obs.Facts[0].Statement
			wantPrefix := "样本格式:" + tc.wantFormat + " arch=" + tc.wantArch + " size="
			if !strings.HasPrefix(statement, wantPrefix) {
				t.Errorf("statement = %q, want prefix %q", statement, wantPrefix)
			}
			if len(obs.Assets) != 1 {
				t.Fatalf("want 1 asset, got %d", len(obs.Assets))
			}
			asset := obs.Assets[0]
			if asset.Kind != "artifact" || asset.Value != "artifact:"+path {
				t.Errorf("asset = %+v", asset)
			}
			if got, _ := asset.Props["format"].(string); got != tc.wantFormat {
				t.Errorf("asset format = %q, want %q", got, tc.wantFormat)
			}
			sum, _ := asset.Props["sha256"].(string)
			if len(sum) != 64 {
				t.Errorf("asset sha256 = %q", sum)
			}
			if ev, ok := obs.Facts[0].Evidence["path"].(string); !ok || ev != path {
				t.Errorf("fact evidence path = %v", obs.Facts[0].Evidence["path"])
			}
		})
	}
}

// ---- register ---------------------------------------------------------------

func TestArtifactRegisterCopiesAndHashes(t *testing.T) {
	srcDir := t.TempDir()
	payload := []byte("youkai register fixture payload")
	src := writeFixture(t, srcDir, "sample.bin", payload)
	env := testEnv(t)

	obs, err := Run(context.Background(), env, "artifact_register", map[string]any{
		"path": src, "copy": true,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	sum := sha256Bytes(payload)
	if len(obs.Facts) != 1 || !strings.Contains(obs.Facts[0].Statement, sum) {
		t.Fatalf("fact does not carry sha256: %+v", obs.Facts)
	}
	if ev, _ := obs.Facts[0].Evidence["executed"].(bool); ev {
		t.Error("register claims to have executed the sample")
	}
	entries, err := os.ReadDir(env.ArtifactDir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly 1 isolated copy, got %d", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), sum[:16]+"-") {
		t.Errorf("isolated name %q does not start with sha prefix", entries[0].Name())
	}
	copied, err := os.ReadFile(filepath.Join(env.ArtifactDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read copy: %v", err)
	}
	if string(copied) != string(payload) {
		t.Error("isolated copy differs from source")
	}
	isolated, _ := obs.Facts[0].Evidence["isolated_path"].(string)
	if isolated == "" || !strings.HasPrefix(isolated, env.ArtifactDir) {
		t.Errorf("isolated_path = %q", isolated)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(isolated)
		if err != nil {
			t.Fatalf("stat copy: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("isolated copy mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestArtifactRegisterCopyFalseWritesNothing(t *testing.T) {
	srcDir := t.TempDir()
	src := writeFixture(t, srcDir, "sample.bin", []byte("no copy please"))
	env := testEnv(t)
	obs, err := Run(context.Background(), env, "artifact_register", map[string]any{
		"path": src, "copy": false,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := os.Stat(env.ArtifactDir); !os.IsNotExist(err) {
		t.Errorf("ArtifactDir was created despite copy=false (err=%v)", err)
	}
	if ev, _ := obs.Facts[0].Evidence["isolated_path"].(string); ev != "" {
		t.Errorf("isolated_path = %q, want empty", ev)
	}
}

func TestArtifactRegisterRefusesOversize(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	big := filepath.Join(dir, "huge.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatalf("create big: %v", err)
	}
	if err := f.Truncate(maxFileSize + 1); err != nil {
		t.Fatalf("truncate big: %v", err)
	}
	_ = f.Close()
	_, err = Run(context.Background(), env, "artifact_register", map[string]any{"path": big})
	if err == nil {
		t.Fatal("oversize sample was accepted")
	}
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "64 MiB") {
		t.Errorf("oversize error = %v, want ErrRefused with 64 MiB", err)
	}
	if _, statErr := os.Stat(env.ArtifactDir); !os.IsNotExist(statErr) {
		t.Errorf("ArtifactDir was created for a refused sample (err=%v)", statErr)
	}
}

func TestArtifactRegisterRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	target := writeFixture(t, dir, "real.bin", []byte("symlink target"))
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink on this machine: %v", err)
	}
	_, err := Run(context.Background(), env, "artifact_register", map[string]any{"path": link})
	if err == nil || !strings.Contains(err.Error(), "符号链接") {
		t.Errorf("symlink error = %v, want a refusal naming 符号链接", err)
	}
}

func TestRunRequiresEnv(t *testing.T) {
	if _, err := Run(context.Background(), nil, "artifact_identify", map[string]any{"path": "x"}); err == nil {
		t.Error("Run accepted a nil Env")
	}
}

func TestArtifactRegisterRequiresArtifactDir(t *testing.T) {
	src := writeFixture(t, t.TempDir(), "sample.bin", []byte("x"))
	env := &Env{ArtifactDir: ""}
	_, err := Run(context.Background(), env, "artifact_register", map[string]any{"path": src})
	if err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused for missing ArtifactDir", err)
	}
}

// ---- checksec ---------------------------------------------------------------

func TestChecksecELFPartialAndPIE(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)

	partial := writeFixture(t, dir, "partial.elf", buildELF(t, elfSpec{stack: true, relro: true}))
	obs, err := Run(context.Background(), env, "checksec", map[string]any{"path": partial})
	if err != nil {
		t.Fatalf("checksec partial: %v", err)
	}
	statement := obs.Facts[0].Statement
	want := "checksec:elf pie=false nx=true relro=partial canary=unknown"
	if statement != want {
		t.Errorf("statement = %q, want %q", statement, want)
	}
	if len(obs.Findings) != 1 || !strings.Contains(obs.Findings[0].Title, "不是 PIE") {
		t.Errorf("partial findings = %+v, want only the non-PIE info finding", obs.Findings)
	}

	full := writeFixture(t, dir, "full.elf", buildELF(t, elfSpec{
		eType: etDyn, stack: true, relro: true, dynamic: true,
	}))
	obs, err = Run(context.Background(), env, "checksec", map[string]any{"path": full})
	if err != nil {
		t.Fatalf("checksec full: %v", err)
	}
	statement = obs.Facts[0].Statement
	if statement != "checksec:elf pie=true nx=true relro=full canary=unknown" {
		t.Errorf("full RELRO statement = %q", statement)
	}
	for _, f := range obs.Findings {
		if strings.Contains(f.Title, "RELRO") || strings.Contains(f.Title, "NX") || strings.Contains(f.Title, "canary") {
			t.Errorf("full-relro binary produced a false hardening finding: %q", f.Title)
		}
	}
}

func TestChecksecELFReportsRealAbsences(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "weak.elf", buildELF(t, elfSpec{
		stack: true, stackFlags: 0x7, relro: false,
	}))
	obs, err := Run(context.Background(), env, "checksec", map[string]any{"path": path})
	if err != nil {
		t.Fatalf("checksec: %v", err)
	}
	statement := obs.Facts[0].Statement
	if !strings.Contains(statement, "nx=false") || !strings.Contains(statement, "relro=none") {
		t.Errorf("statement = %q, want nx=false relro=none", statement)
	}
	titles := map[string]bool{}
	for _, f := range obs.Findings {
		titles[f.Title] = true
		if f.Where != path {
			t.Errorf("finding where = %q, want %q", f.Where, path)
		}
	}
	if !titles["ELF 未启用 NX(栈可执行)"] {
		t.Errorf("missing NX finding: %v", titles)
	}
	if !titles["ELF 未启用 RELRO"] {
		t.Errorf("missing RELRO finding: %v", titles)
	}
	if strings.Contains(statement, "canary=yes") || strings.Contains(statement, "canary=no") {
		t.Errorf("canary was guessed instead of unknown: %q", statement)
	}
}

func TestChecksecPE(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)

	hardened := writeFixture(t, dir, "hardened.exe", buildPE(t, 0x4160))
	obs, err := Run(context.Background(), env, "checksec", map[string]any{"path": hardened})
	if err != nil {
		t.Fatalf("checksec PE: %v", err)
	}
	statement := obs.Facts[0].Statement
	want := "checksec:pe pie=true nx=true relro=n/a canary=unknown"
	if statement != want {
		t.Errorf("statement = %q, want %q", statement, want)
	}
	for _, f := range obs.Findings {
		if strings.Contains(f.Title, "ASLR") || strings.Contains(f.Title, "DEP") || strings.Contains(f.Title, "CFG") {
			t.Errorf("hardened PE produced a mitigation finding: %q", f.Title)
		}
	}

	weak := writeFixture(t, dir, "weak.exe", buildPE(t, 0))
	obs, err = Run(context.Background(), env, "checksec", map[string]any{"path": weak})
	if err != nil {
		t.Fatalf("checksec weak PE: %v", err)
	}
	if !strings.Contains(obs.Facts[0].Statement, "pie=false") || !strings.Contains(obs.Facts[0].Statement, "nx=false") {
		t.Errorf("weak statement = %q", obs.Facts[0].Statement)
	}
	titles := map[string]bool{}
	for _, f := range obs.Findings {
		titles[f.Title] = true
	}
	if !titles["PE 未启用 ASLR(DYNAMIC_BASE)"] || !titles["PE 未启用 DEP/NX(NX_COMPAT)"] {
		t.Errorf("weak PE findings = %v", titles)
	}
}

func TestChecksecRefusesUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "sample.apk", buildAPK(t, false))
	_, err := Run(context.Background(), env, "checksec", map[string]any{"path": path})
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// ---- secrets ----------------------------------------------------------------

func TestSecretsRedaction(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "leak.txt", []byte(secretFixture))
	obs, err := Run(context.Background(), env, "secrets", map[string]any{"path": path})
	if err != nil {
		t.Fatalf("secrets: %v", err)
	}
	blob := observationJSON(t, obs)
	for _, secret := range secretFixtureValues {
		if strings.Contains(blob, secret) {
			t.Fatalf("full secret leaked into output: %q", clipString(secret, 24))
		}
	}
	if len(obs.Findings) < 5 {
		t.Fatalf("want at least 5 findings, got %d", len(obs.Findings))
	}
	sawAWS := false
	sawCritical := false
	for _, f := range obs.Findings {
		if f.Kind != "secret" {
			t.Errorf("finding kind = %q, want secret", f.Kind)
		}
		if f.Where == "" || !strings.Contains(f.Where, ":") {
			t.Errorf("finding has no location: %+v", f)
		}
		if ledger.NormaliseSeverity(f.Severity) != f.Severity {
			t.Errorf("severity %q is not normalised", f.Severity)
		}
		if f.Severity == "critical" {
			sawCritical = true
		}
		preview, _ := f.Evidence["preview"].(string)
		if preview == "" {
			t.Errorf("finding has no masked preview: %+v", f)
		}
		if strings.HasPrefix(preview, "AKIA") {
			sawAWS = true
		}
		if strings.Contains(f.Detail, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("detail leaked the AWS key")
		}
	}
	if !sawAWS {
		t.Error("no AWS masked preview (expected AKIA…)")
	}
	if !sawCritical {
		t.Error("no critical finding for the private key")
	}
	if !strings.Contains(obs.Facts[0].Statement, "已脱敏") && !strings.Contains(obs.Facts[0].Statement, "脱敏") {
		t.Errorf("fact does not say redacted: %q", obs.Facts[0].Statement)
	}
}

func TestSecretsDirectoryMode(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	writeFixture(t, dir, "a.txt", []byte(secretFixture))
	writeFixture(t, dir, "b.bin", []byte{0x00, 0x01, 0x02, 0x03})
	obs, err := Run(context.Background(), env, "secrets", map[string]any{"dir": dir})
	if err != nil {
		t.Fatalf("secrets dir: %v", err)
	}
	if len(obs.Findings) == 0 {
		t.Fatal("directory sweep found nothing")
	}
	blob := observationJSON(t, obs)
	for _, secret := range secretFixtureValues {
		if strings.Contains(blob, secret) {
			t.Fatalf("full secret leaked in dir mode: %q", clipString(secret, 24))
		}
	}
}

// ---- strings ----------------------------------------------------------------

func TestStringsCountsAndRedaction(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	data := "visit https://user:pass@example.com/path?token=abc123secret now\n" +
		"C:\\Program Files\\app\\libfoo.dll\n" +
		"DB_PASSWORD = \"SuperSecretPassword123\"\n" +
		"plain hello world line\n" +
		"p\x00r\x00e\x00f\x00i\x00x\x00e\x00d\x00\x00\x00"
	path := writeFixture(t, dir, "strings.bin", []byte(data))
	obs, err := Run(context.Background(), env, "strings", map[string]any{
		"path": path, "min_length": 4, "limit": 50,
	})
	if err != nil {
		t.Fatalf("strings: %v", err)
	}
	statement := obs.Facts[0].Statement
	if !strings.Contains(statement, "utf16le=") || !strings.Contains(statement, "已脱敏") {
		t.Errorf("statement = %q", statement)
	}
	if !strings.Contains(statement, "url=1") || !strings.Contains(statement, "path=") {
		t.Errorf("statement counts look wrong: %q", statement)
	}
	blob := observationJSON(t, obs)
	for _, secret := range []string{"SuperSecretPassword123", "abc123secret", "user:pass"} {
		if strings.Contains(blob, secret) {
			t.Errorf("strings output leaked %q", secret)
		}
	}
	// UTF-16LE runs must be counted separately from ASCII.
	evidence, _ := json.Marshal(obs.Facts[0].Evidence)
	if !strings.Contains(string(evidence), "utf16le_count") {
		t.Error("evidence has no utf16le_count")
	}
	if !strings.Contains(statement, "utf16le=1") {
		t.Errorf("UTF-16LE run was not counted: %q", statement)
	}
}

// ---- mobile ----------------------------------------------------------------

func TestMobileUnpackInventoryAndExtract(t *testing.T) {
	dir := t.TempDir()
	apkPath := writeFixture(t, dir, "sample.apk", buildAPK(t, true))
	env := testEnv(t)

	obs, err := Run(context.Background(), env, "mobile_unpack", map[string]any{"path": apkPath})
	if err != nil {
		t.Fatalf("mobile_unpack: %v", err)
	}
	statement := obs.Facts[0].Statement
	if !strings.Contains(statement, "AndroidManifest.xml=true") {
		t.Errorf("statement = %q", statement)
	}
	if len(obs.Assets) != 3 {
		t.Errorf("want 3 assets (2 dex + 1 lib), got %d: %+v", len(obs.Assets), obs.Assets)
	}
	if _, err := os.Stat(env.ArtifactDir); !os.IsNotExist(err) {
		t.Errorf("extract=false still created ArtifactDir (err=%v)", err)
	}

	obs, err = Run(context.Background(), env, "mobile_unpack", map[string]any{
		"path": apkPath, "extract": true,
	})
	if err != nil {
		t.Fatalf("mobile_unpack extract: %v", err)
	}
	sum, _, err := sha256File(apkPath)
	if err != nil {
		t.Fatalf("hash apk: %v", err)
	}
	outDir := filepath.Join(env.ArtifactDir, "mobile-"+sum[:16])
	if _, err := os.Stat(filepath.Join(outDir, "assets", "config.json")); err != nil {
		t.Errorf("asset was not extracted: %v", err)
	}
	outside := filepath.Join(env.ArtifactDir, "evil.txt")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("zip-slip entry escaped the extraction dir (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(env.ArtifactDir), "evil.txt")); !os.IsNotExist(err) {
		t.Errorf("zip-slip entry escaped ArtifactDir (err=%v)", err)
	}
	foundSkip := false
	for _, fact := range obs.Facts {
		if strings.Contains(fact.Statement, "已解包") && strings.Contains(fact.Statement, "跳过") {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("extraction fact does not mention the skipped traversal entry: %+v", obs.Facts)
	}
	if len(obs.Findings) == 0 {
		t.Error("post-extraction secret re-scan found nothing")
	}
	blob := observationJSON(t, obs)
	if strings.Contains(blob, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("mobile_unpack leaked the full AWS key")
	}
}

func TestZipEntryRelRefusesTraversal(t *testing.T) {
	bad := []string{"../evil.txt", "..\\evil.txt", "/etc/passwd", "C:/windows/system32/x", "a/../../b"}
	for _, name := range bad {
		if _, err := zipEntryRel(name); err == nil {
			t.Errorf("zipEntryRel(%q) accepted a traversal path", name)
		}
	}
	good, err := zipEntryRel("lib/arm64-v8a/libx.so")
	if err != nil || filepath.ToSlash(good) != "lib/arm64-v8a/libx.so" {
		t.Errorf("zipEntryRel(good) = %q, %v", good, err)
	}
}

func TestEnsureWithinRefusesEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := ensureWithin(root, filepath.Join(root, "ok.txt")); err != nil {
		t.Errorf("valid child refused: %v", err)
	}
	if _, err := ensureWithin(root, filepath.Join(root, "..", "escape.txt")); err == nil {
		t.Error("escape via .. was accepted")
	}
	if _, err := ensureWithin(root, filepath.Join(root, "sub", "..", "..", "escape.txt")); err == nil {
		t.Error("escape via nested .. was accepted")
	}
}

// ---- dataflow ---------------------------------------------------------------

func TestDataflowHeuristic(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	source := `#include <stdio.h>
int main(int argc, char **argv) {
    char buf[64];
    strcpy(buf, argv[1]);
    system(buf);
    return 0;
}
`
	path := writeFixture(t, dir, "vuln.c", []byte(source))
	obs, err := Run(context.Background(), env, "dataflow", map[string]any{"path": dir})
	if err != nil {
		t.Fatalf("dataflow: %v", err)
	}
	if len(obs.Findings) < 2 {
		t.Fatalf("want >=2 dataflow findings, got %d", len(obs.Findings))
	}
	sinks := map[string]bool{}
	for _, f := range obs.Findings {
		if f.Kind != "dataflow" {
			t.Errorf("kind = %q", f.Kind)
		}
		if !strings.HasPrefix(f.Where, path+":") {
			t.Errorf("where = %q, want %s:line", f.Where, path)
		}
		if !strings.Contains(f.Detail, "启发式") {
			t.Errorf("detail does not admit the heuristic: %q", f.Detail)
		}
		if !strings.Contains(f.Detail, "argv") {
			t.Errorf("taint path missing source: %q", f.Detail)
		}
		for _, sink := range []string{"strcpy", "system"} {
			if strings.Contains(f.Title, sink) {
				sinks[sink] = true
			}
		}
	}
	if !sinks["strcpy"] || !sinks["system"] {
		t.Errorf("missing sink findings: %v", sinks)
	}
	if !strings.Contains(obs.Facts[0].Statement, "启发式") {
		t.Errorf("fact does not admit the heuristic: %q", obs.Facts[0].Statement)
	}
}

// ---- sarif ------------------------------------------------------------------

func TestSARIFGeneration(t *testing.T) {
	env := testEnv(t)
	findings := []any{
		map[string]any{"title": "测试候选一", "severity": "high", "kind": "hardening", "where": "C:\\samples\\a.exe", "detail": "demo"},
		map[string]any{"title": "测试候选二", "severity": "low", "kind": "secret", "where": "src/x.c:12", "detail": "demo"},
	}
	obs, err := Run(context.Background(), env, "sarif", map[string]any{
		"engagement": "unit-test", "findings": findings,
	})
	if err != nil {
		t.Fatalf("sarif: %v", err)
	}
	outPath := filepath.Join(env.ArtifactDir, "report.sarif")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if doc["$schema"] == nil {
		t.Error("missing $schema")
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d", len(runs))
	}
	run, _ := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("results = %d, want 2", len(results))
	}
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("rules = %d, want 2", len(rules))
	}
	if !strings.Contains(obs.Facts[0].Statement, outPath) {
		t.Errorf("fact does not name the SARIF path: %q", obs.Facts[0].Statement)
	}
}

func TestSARIFRejectsBadInput(t *testing.T) {
	env := testEnv(t)
	if _, err := Run(context.Background(), env, "sarif", map[string]any{}); err == nil {
		t.Error("sarif accepted empty args")
	}
}

// ---- firmware ---------------------------------------------------------------

func TestFirmwareDetectionOnly(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	payload := append([]byte("hsqs"), make([]byte, 256)...)
	payload = append(payload, []byte{0x1f, 0x8b, 0x08}...)
	path := writeFixture(t, dir, "fw.bin", payload)
	obs, err := Run(context.Background(), env, "firmware_extract", map[string]any{"path": path})
	if err != nil {
		t.Fatalf("firmware: %v", err)
	}
	if len(obs.Facts) < 2 {
		t.Fatalf("want detection + degraded facts, got %d", len(obs.Facts))
	}
	detection := obs.Facts[0]
	if !strings.Contains(detection.Statement, "未解包") {
		t.Errorf("detection fact = %q", detection.Statement)
	}
	sigs, _ := detection.Evidence["signatures"].([]map[string]any)
	if len(sigs) == 0 {
		t.Fatalf("no signatures in evidence: %+v", detection.Evidence)
	}
	if !strings.Contains(obs.Facts[1].Statement, "未执行") ||
		!strings.Contains(obs.Facts[1].Statement, "外部工具") {
		t.Errorf("degraded fact = %q", obs.Facts[1].Statement)
	}
	if _, err := os.Stat(env.ArtifactDir); !os.IsNotExist(err) {
		t.Errorf("firmware detection wrote files (err=%v)", err)
	}
}

// ---- external backends ------------------------------------------------------

func TestDangerousImportMatching(t *testing.T) {
	yes := map[string]string{
		"strcpy":             "strcpy",
		"strcpy@GLIBC_2.2.5": "strcpy",
		"execve":             "exec",
		"execvp":             "exec",
		"system":             "system",
		"memcpy":             "memcpy",
	}
	for name, want := range yes {
		d, ok := matchDangerousName(name)
		if !ok || d.Name != want {
			t.Errorf("matchDangerousName(%q) = %+v,%v want %q", name, d, ok, want)
		}
	}
	for _, name := range []string{"fmt.Sprintf", "syscall.Exec", "os/exec.Command", "execute", "systemstack", "passwords", "libc_system"} {
		if d, ok := matchDangerousName(name); ok {
			t.Errorf("matchDangerousName(%q) false-positived as %q", name, d.Name)
		}
	}
	lines := []struct {
		line string
		want string
		ok   bool
	}{
		{"00000001401a0980 T flag.(*FlagSet).sprintf", "sprintf", false},
		{"0000000000000000 T fmt.Sprintf", "sprintf", false},
		{"00000001401227a0 T flag.(*FlagSet).Sprintf", "sprintf", false},
		{"0000000000401000 T strcpy", "strcpy", true},
		{"                 U strcpy@GLIBC_2.2.5", "strcpy", true},
		{"0000000000000000 T os/exec.Command", "exec", false},
		{"0000000000000000 T execve", "exec", true},
	}
	for _, tc := range lines {
		var danger dangerousImport
		for _, d := range dangerousImports {
			if d.Name == tc.want {
				danger = d
			}
		}
		if got := dangerInLine(tc.line, danger); got != tc.ok {
			t.Errorf("dangerInLine(%q) = %v, want %v", tc.line, got, tc.ok)
		}
	}
}

func TestSymbolsNeverFabricates(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "sample.elf", buildELF(t, elfSpec{stack: true, relro: true}))
	obs, err := Run(context.Background(), env, "symbols", map[string]any{"path": path})
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	if len(obs.Facts) == 0 {
		t.Fatal("no fact emitted")
	}
	statement := obs.Facts[0].Statement
	if !strings.HasPrefix(statement, "symbols:") {
		t.Errorf("statement = %q", statement)
	}
	backend, _ := obs.Facts[0].Evidence["backend"].(string)
	t.Logf("symbols backend=%s statement=%q", backend, statement)
	if backend == "none" || strings.Contains(statement, "未执行") {
		if len(obs.Findings) != 0 {
			t.Error("symbols fabricated findings without a backend")
		}
		if backend != "none" {
			t.Errorf("degraded backend = %q, want none", backend)
		}
		return
	}
	switch backend {
	case "nm", "readelf", "objdump":
	default:
		t.Errorf("unexpected backend %q", backend)
	}
}

func TestDisasmBackendPolicy(t *testing.T) {
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "sample.elf", buildELF(t, elfSpec{stack: true, relro: true}))
	obs, err := Run(context.Background(), env, "disasm", map[string]any{"path": path})
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("disasm error = %v, want ErrUnavailable when objdump is missing", err)
		}
		return
	}
	if len(obs.Facts) == 0 || !strings.Contains(obs.Facts[0].Statement, "backend=objdump") {
		t.Errorf("disasm facts = %+v", obs.Facts)
	}
	t.Logf("disasm statement=%q", obs.Facts[0].Statement)
}

func TestDecompileWithoutBackendIsTyped(t *testing.T) {
	t.Setenv("VERDEX_GHIDRA", "")
	t.Setenv("VERDEX_JADX", "")
	dir := t.TempDir()
	env := testEnv(t)
	path := writeFixture(t, dir, "sample.elf", buildELF(t, elfSpec{stack: true, relro: true}))
	_, err := Run(context.Background(), env, "decompile", map[string]any{"path": path})
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// ---- doctor -----------------------------------------------------------------

func TestDoctor(t *testing.T) {
	obs, err := Run(context.Background(), testEnv(t), "doctor", nil)
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if len(obs.Facts) != 1 {
		t.Fatalf("want 1 fact, got %d", len(obs.Facts))
	}
	statement := obs.Facts[0].Statement
	if !strings.HasPrefix(statement, "doctor:") || !strings.Contains(statement, "分析后端") {
		t.Errorf("statement = %q", statement)
	}
	backends, _ := obs.Facts[0].Evidence["backends"].([]map[string]any)
	if len(backends) == 0 {
		t.Fatalf("no backend entries: %+v", obs.Facts[0].Evidence)
	}
	for _, entry := range backends {
		if _, ok := entry["status"]; !ok {
			t.Errorf("backend entry has no status: %+v", entry)
		}
	}
	if ev, _ := obs.Facts[0].Evidence["executed"].(bool); ev {
		t.Error("doctor claims to have executed something")
	}
	if !strings.Contains(statement, "可用=") || !strings.Contains(statement, "降级=") {
		t.Errorf("doctor does not report availability/degradation: %q", statement)
	}
}

// ---- tier 2 -----------------------------------------------------------------

func TestPwnTemplateWritesSkeletonOnly(t *testing.T) {
	env := testEnv(t)
	obs, err := Run(context.Background(), env, "pwn_template", map[string]any{
		"binary": "./chall", "arch": "amd64", "remote": "127.0.0.1:31337",
	})
	if err != nil {
		t.Fatalf("pwn_template: %v", err)
	}
	if len(obs.Facts) != 1 {
		t.Fatalf("want 1 fact, got %d", len(obs.Facts))
	}
	path, _ := obs.Facts[0].Evidence["path"].(string)
	if path == "" || !strings.HasPrefix(path, env.ArtifactDir) {
		t.Fatalf("artifact path = %q", path)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read skeleton: %v", err)
	}
	if !strings.Contains(string(text), "from pwn import *") {
		t.Error("skeleton is not a pwntools script")
	}
	if ev, _ := obs.Facts[0].Evidence["executed"].(bool); ev {
		t.Error("pwn_template claims execution")
	}
	if _, ok := obs.Facts[0].Evidence["text"]; ok {
		t.Error("generated text was put into evidence")
	}
}

func TestDownloadIsNotImplemented(t *testing.T) {
	_, err := Run(context.Background(), testEnv(t), "download", map[string]any{"url": "http://example.invalid/x"})
	if err == nil || !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
	if !strings.Contains(err.Error(), "discipline.Guard") {
		t.Errorf("error does not name the required path: %v", err)
	}
}
