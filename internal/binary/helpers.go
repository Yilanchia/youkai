package binary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"youkai/internal/ledger"
)

const (
	// maxFileSize is the hard cap for every capability. It bounds memory and
	// regex time, and keeps one huge sample from stalling the engine.
	maxFileSize int64 = 64 << 20 // 64 MiB
	// maxDirFileSize bounds a single file during a directory sweep (secrets,
	// dataflow), where the total is separately bounded.
	maxDirFileSize int64 = 16 << 20
	// maxDirBytes bounds the total bytes a directory sweep will read.
	maxDirBytes int64 = 32 << 20
	// maxDirFiles bounds how many files a directory sweep will visit.
	maxDirFiles = 5000
	// maxToolOutput bounds external backend stdout (bytes kept).
	maxToolOutput = 4 << 20
	// defaultToolTimeout bounds every external tool invocation.
	defaultToolTimeout = 30 * time.Second
)

// ---- argument helpers -------------------------------------------------------

func argString(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	switch v := args[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func argInt(args map[string]any, key string, def int) int {
	if args == nil {
		return def
	}
	switch v := args[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case int32:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func argBool(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	switch v := args[key].(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	case float64:
		return v != 0
	}
	return def
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- paths -----------------------------------------------------------------

// inputFilePath resolves an analysis input and enforces the read-only rules:
// a regular file, inside the size cap, and not a symlink unless the caller
// explicitly allows following one.
func inputFilePath(raw string, followSymlink bool) (string, int64, error) {
	if strings.TrimSpace(raw) == "" {
		return "", 0, fmt.Errorf("%w: 参数 path 必填", ErrRefused)
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 解析路径 %q: %v", ErrRefused, raw, err)
	}
	linkInfo, err := os.Lstat(abs)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 读取路径信息 %s: %v", ErrRefused, abs, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		if !followSymlink {
			return "", 0, fmt.Errorf("%w: 拒绝符号链接 %s", ErrRefused, abs)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return "", 0, fmt.Errorf("%w: 解析符号链接 %s: %v", ErrRefused, abs, err)
		}
		if !info.Mode().IsRegular() {
			return "", 0, fmt.Errorf("%w: 不是普通文件 %s", ErrRefused, abs)
		}
		if info.Size() > maxFileSize {
			return "", 0, fmt.Errorf("%w: 文件 %d 字节超过 64 MiB 上限: %s", ErrRefused, info.Size(), abs)
		}
		return abs, info.Size(), nil
	}
	if !linkInfo.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: 不是普通文件 %s", ErrRefused, abs)
	}
	if linkInfo.Size() > maxFileSize {
		return "", 0, fmt.Errorf("%w: 文件 %d 字节超过 64 MiB 上限: %s", ErrRefused, linkInfo.Size(), abs)
	}
	return abs, linkInfo.Size(), nil
}

// inputPathAllowDir resolves an input that may be a directory (secrets,
// dataflow). Files are size-capped; directories are walked under separate caps.
func inputPathAllowDir(raw string) (string, os.FileInfo, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil, fmt.Errorf("%w: 参数 path 必填", ErrRefused)
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: 解析路径 %q: %v", ErrRefused, raw, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("%w: 读取路径信息 %s: %v", ErrRefused, abs, err)
	}
	if info.Mode().IsRegular() && info.Size() > maxFileSize {
		return "", nil, fmt.Errorf("%w: 文件 %d 字节超过 64 MiB 上限: %s", ErrRefused, info.Size(), abs)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return "", nil, fmt.Errorf("%w: 既不是普通文件也不是目录: %s", ErrRefused, abs)
	}
	return abs, info, nil
}

// artifactDir resolves and creates Env.ArtifactDir. A capability that must
// write refuses to run without one; nothing is ever written elsewhere.
func artifactDir(env *Env) (string, error) {
	if env == nil || strings.TrimSpace(env.ArtifactDir) == "" {
		return "", fmt.Errorf("%w: ArtifactDir 未配置,拒绝写盘", ErrRefused)
	}
	abs, err := filepath.Abs(env.ArtifactDir)
	if err != nil {
		return "", fmt.Errorf("%w: 解析 ArtifactDir: %v", ErrRefused, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("%w: 创建 ArtifactDir %s: %v", ErrRefused, abs, err)
	}
	return abs, nil
}

// ensureWithin returns target resolved absolute, or refuses when it is not
// strictly inside root. Containment is checked on cleaned absolute paths, so
// ".." segments and mixed separators cannot escape.
func ensureWithin(root, target string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("%w: 解析根目录 %s: %v", ErrRefused, root, err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("%w: 解析目标路径 %s: %v", ErrRefused, target, err)
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return "", fmt.Errorf("%w: 目标 %s 不在根目录 %s 内", ErrRefused, targetAbs, rootAbs)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: 路径穿越被拒绝(目标 %s 在 %s 之外)", ErrRefused, targetAbs, rootAbs)
	}
	return targetAbs, nil
}

// writeArtifact writes one file inside ArtifactDir with mode 0600. name must be
// a plain file name; the containment check is a second line of defence.
func writeArtifact(env *Env, name string, data []byte) (string, error) {
	dir, err := artifactDir(env)
	if err != nil {
		return "", err
	}
	if name == "" || name == "." || strings.ContainsAny(name, `/\:`) {
		return "", fmt.Errorf("%w: 非法产物文件名 %q", ErrRefused, name)
	}
	path, err := ensureWithin(dir, filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("%w: 写入 %s: %v", ErrRefused, path, err)
	}
	return path, nil
}

// ---- hashing ----------------------------------------------------------------

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 打开 %s: %v", ErrRefused, path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 读取 %s: %v", ErrRefused, path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func sha256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readBounded reads at most max bytes from path, so a backend that emits a huge
// file cannot exhaust memory.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		data = data[:max]
	}
	return data, nil
}

// ---- external tools ---------------------------------------------------------

// findTool resolves an analysis tool: the env override first (a full path or a
// name), then PATH. It never accepts user input, only fixed names.
func findTool(name, envVar string) (string, bool) {
	if envVar != "" {
		if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
			if info, err := os.Stat(v); err == nil && !info.IsDir() {
				return v, true
			}
			if p, err := exec.LookPath(v); err == nil {
				return p, true
			}
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	return "", false
}

// limitedBuffer keeps at most max bytes and drops the rest, so a malicious or
// huge binary cannot make a backend exhaust memory.
type limitedBuffer struct {
	max       int
	buf       []byte
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.max <= 0 {
		w.truncated = w.truncated || len(p) > 0
		return len(p), nil
	}
	room := w.max - len(w.buf)
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		w.buf = append(w.buf, p[:room]...)
		w.truncated = true
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *limitedBuffer) String() string { return string(w.buf) }

// runTool runs one whitelisted analysis tool with explicit argv, no shell, and
// a hard timeout. It returns stdout (bounded), whether stdout was truncated,
// and an error that includes a bounded stderr excerpt.
func runTool(ctx context.Context, timeout time.Duration, tool string, args []string, maxOut int) (string, bool, error) {
	if tool == "" {
		return "", false, fmt.Errorf("%w: 空的后端命令", ErrUnavailable)
	}
	if timeout <= 0 {
		timeout = defaultToolTimeout
	}
	if maxOut <= 0 {
		maxOut = maxToolOutput
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, tool, args...)
	out := &limitedBuffer{max: maxOut}
	errBuf := &limitedBuffer{max: 16 << 10}
	cmd.Stdout = out
	cmd.Stderr = errBuf
	// An empty Env is not what we want: backends need PATH/TEMP. Inherit as-is.
	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return out.String(), out.truncated, fmt.Errorf("%w: %s 超时(%s)", ErrUnavailable, filepath.Base(tool), timeout)
	}
	if err != nil {
		detail := strings.TrimSpace(errBuf.String())
		if detail == "" {
			detail = err.Error()
		}
		return out.String(), out.truncated, fmt.Errorf("%w: %s 运行失败: %s", ErrUnavailable, filepath.Base(tool), clipString(detail, 300))
	}
	return out.String(), out.truncated, nil
}

// probeVersion asks a tool for its version, bounded. It is used only by doctor,
// never on an artifact.
func probeVersion(ctx context.Context, tool string) string {
	out, _, err := runTool(ctx, 8*time.Second, tool, []string{"--version"}, 4<<10)
	if err != nil {
		if out == "" {
			return "present (版本探测失败)"
		}
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if line == "" {
		return "present"
	}
	return clipString(line, 160)
}

// ---- text helpers -----------------------------------------------------------

func clipString(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	// Do not split a UTF-8 rune in half.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// shannonEntropy is used only to filter low-entropy false positives.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(s))
		e -= p * math.Log2(p)
	}
	return e
}

// ---- ledger seed helpers ----------------------------------------------------

func newFact(statement string, evidence map[string]any, tags []string, anchors []string) ledger.FactSeed {
	return ledger.FactSeed{Statement: statement, Evidence: evidence, Tags: tags, Anchors: anchors}
}

func newFinding(title, severity, kind, where, detail string, evidence map[string]any, tags []string, anchors []string) ledger.FindingSeed {
	return ledger.FindingSeed{
		Title:    title,
		Severity: ledger.NormaliseSeverity(severity),
		Kind:     kind,
		Where:    where,
		Detail:   detail,
		Evidence: evidence,
		Tags:     tags,
		Anchors:  anchors,
	}
}

// evidenceWithLocation guarantees the "must carry a location" rule even if a
// caller forgets: where is always present when non-empty.
func evidenceWithLocation(where string, kv map[string]any) map[string]any {
	out := make(map[string]any, len(kv)+1)
	for k, v := range kv {
		out[k] = v
	}
	if where != "" {
		out["where"] = where
	}
	return out
}

// orAll renders an empty symbol filter as "all" in fact statements.
func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}
