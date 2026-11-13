package binary

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"youkai/internal/ledger"
)

var (
	objdumpLineRe   = regexp.MustCompile(`^\s*([0-9a-fA-F]+):\s+(.*)$`)
	angleTargetRe   = regexp.MustCompile(`<([^>]+)>`)
	callishRe       = regexp.MustCompile(`(?i)\b(callq?|jmpq?|bl|blx)\b`)
	javaExecRe      = regexp.MustCompile(`(?i)\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder|DexClassLoader|loadLibrary)\b`)
	javaEvalRe      = regexp.MustCompile(`(?i)\b(?:eval|exec)\s*\(`)
	disasmLineLimit = 20000
)

// disasmCapability disassembles through a whitelisted backend. The sample is
// never executed: objdump only reads bytes, jadx only parses the APK.
func disasmCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	fi, err := sniffFormat(path, size)
	if err != nil {
		return ledger.Observation{}, err
	}
	symbol := argString(args, "symbol")
	switch fi.Format {
	case "ELF", "PE":
		return disasmWithObjdump(ctx, path, fi.Format, symbol)
	case "APK", "DEX":
		return disasmWithJadx(ctx, env, path, fi.Format, symbol)
	case "Mach-O":
		// GNU objdump can read Mach-O when built with that BFD target; if this
		// build cannot, the backend error is reported instead of guessing.
		return disasmWithObjdump(ctx, path, fi.Format, symbol)
	default:
		return ledger.Observation{}, fmt.Errorf("%w: disasm 不支持格式 %s", ErrUnavailable, fi.Format)
	}
}

// disasmWithObjdump runs objdump with fixed argv and reports dangerous
// call/jmp targets. Output is capped and parsed line by line in memory.
func disasmWithObjdump(ctx context.Context, path, format, symbol string) (ledger.Observation, error) {
	toolPath, found := findTool("objdump", "")
	if !found {
		return ledger.Observation{}, fmt.Errorf("%w: 未找到 objdump;安装 binutils 后重试", ErrUnavailable)
	}
	if _, runnable := runnableExecutable(toolPath); !runnable {
		return ledger.Observation{}, fmt.Errorf(
			"%w: objdump 入口 %s 是批处理/脚本包装,本包不以 shell 方式运行它", ErrUnavailable, toolPath)
	}
	argv := []string{"-d", "--no-show-raw-insn", "-M", "intel"}
	if symbol != "" {
		argv = append(argv, "--disassemble="+symbol)
	}
	argv = append(argv, path)

	out, truncated, runErr := runTool(ctx, 60*time.Second, toolPath, argv, 8<<20)
	if runErr != nil && strings.TrimSpace(out) == "" {
		return ledger.Observation{}, runErr
	}

	obs := ledger.Observation{}
	seen := map[string]bool{}
	findings := 0
	lines := 0
	for _, line := range strings.Split(out, "\n") {
		if lines >= disasmLineLimit {
			break
		}
		m := objdumpLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		lines++
		addr, text := m[1], m[2]
		if !callishRe.MatchString(text) {
			continue
		}
		target := angleTargetRe.FindStringSubmatch(text)
		if target == nil {
			continue
		}
		danger, isDanger := matchDangerousName(target[1])
		if !isDanger {
			continue
		}
		key := addr + "|" + danger.Name
		if seen[key] || findings >= 200 {
			continue
		}
		seen[key] = true
		findings++
		where := fmt.Sprintf("%s:0x%s", path, addr)
		obs.Findings = append(obs.Findings, newFinding(
			fmt.Sprintf("反汇编显示调用危险函数 %s(%s)", danger.Name, danger.Note),
			danger.Severity, "dangerous-call", where,
			fmt.Sprintf("objdump 在地址 0x%s 看到控制流转入 %s(%s)。这是符号名匹配的启发式候选,参数可控性需人工确认。",
				addr, danger.Name, danger.Note),
			evidenceWithLocation(where, map[string]any{
				"path":     path,
				"format":   strings.ToLower(format),
				"addr":     "0x" + addr,
				"symbol":   danger.Name,
				"insn":     clipString(strings.TrimSpace(text), 160),
				"backend":  "objdump",
				"source":   "external-backend:objdump",
				"executed": false,
			}),
			[]string{"binary", "disasm", "tier1"}, []string{"artifact:" + path},
		))
	}

	statement := fmt.Sprintf("disasm: %s backend=objdump 指令行=%d 危险调用点=%d symbol=%s",
		path, lines, findings, orAll(symbol))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":       path,
		"format":     strings.ToLower(format),
		"backend":    "objdump",
		"symbol":     symbol,
		"line_count": lines,
		"findings":   findings,
		"truncated":  truncated,
		"source":     "external-backend:objdump",
		"executed":   false,
	})
	if runErr != nil {
		evidence["backend_error"] = clipString(runErr.Error(), 300)
	}
	if lines == 0 {
		evidence["note"] = "objdump 未产出可解析的指令行(可能没有该符号或目标格式不受支持)"
	}
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "disasm", "tier1"}, []string{"artifact:" + path}))
	obs.Summary = statement
	return obs, nil
}

// disasmWithJadx decompiles an APK/DEX to Java with jadx and reports dangerous
// API call sites with file:line. jadx writes only under ArtifactDir.
func disasmWithJadx(ctx context.Context, env *Env, path, format, symbol string) (ledger.Observation, error) {
	outDir, err := runJadx(ctx, env, path, "jadx-disasm")
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, files, err := scanDecompiledJava(ctx, outDir, path, "jadx")
	if err != nil {
		return ledger.Observation{}, err
	}
	statement := fmt.Sprintf("disasm: %s backend=jadx 反编译输出文件=%d symbol=%s",
		path, files, orAll(symbol))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":       path,
		"format":     strings.ToLower(format),
		"backend":    "jadx",
		"output_dir": outDir,
		"java_files": files,
		"source":     "external-backend:jadx",
		"executed":   false,
	})
	if symbol != "" {
		evidence["note"] = "jadx 后端不按符号过滤,已忽略 symbol 参数"
	}
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "disasm", "jadx", "tier1"}, []string{"artifact:" + path}))
	obs.Summary = statement
	return obs, nil
}

// runJadx decompiles target into ArtifactDir. The output directory is
// containment-checked before jadx runs.
func runJadx(ctx context.Context, env *Env, target, label string) (string, error) {
	toolPath, found := findTool("jadx", "VERDEX_JADX")
	if !found {
		return "", fmt.Errorf("%w: 未找到 jadx;安装 jadx 或设置 VERDEX_JADX 指向可执行入口", ErrUnavailable)
	}
	if _, runnable := runnableExecutable(toolPath); !runnable {
		return "", fmt.Errorf(
			"%w: jadx 入口 %s 是批处理/脚本包装,本包不以 shell 方式运行它;请指向其可执行 jar/exe 入口", ErrUnavailable, toolPath)
	}
	// jadx needs java for its jar; probe it so the error names the real cause.
	isJar := strings.HasSuffix(strings.ToLower(toolPath), ".jar")
	if isJar {
		if _, ok := findTool("java", ""); !ok {
			return "", fmt.Errorf("%w: jadx 是 .jar,但 PATH 上没有 java;安装 JDK 11+", ErrUnavailable)
		}
	}
	dir, err := artifactDir(env)
	if err != nil {
		return "", err
	}
	out := filepath.Join(dir, fmt.Sprintf("%s-%d", label, time.Now().UnixNano()))
	out, err = ensureWithin(dir, out)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", fmt.Errorf("%w: 创建 jadx 输出目录: %v", ErrRefused, err)
	}
	argv := []string{"-d", out, "--no-res", "-q", target}
	if isJar {
		javaPath, _ := findTool("java", "")
		argv = append([]string{"-jar", toolPath}, argv...)
		toolPath = javaPath
	}
	_, _, runErr := runTool(ctx, 240*time.Second, toolPath, argv, 1<<20)
	if runErr != nil {
		// jadx often returns non-zero after emitting warnings; only fail when
		// nothing was produced.
		if !dirHasJava(out) {
			return "", runErr
		}
	}
	return out, nil
}

func dirHasJava(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".java") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// scanDecompiledJava walks jadx output and reports dangerous API call sites.
func scanDecompiledJava(ctx context.Context, root, sourceArtifact, backend string) (ledger.Observation, int, error) {
	obs := ledger.Observation{}
	javaFiles := 0
	findings := 0
	var totalBytes int64
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".java") {
			return nil
		}
		if javaFiles >= 5000 || findings >= 100 {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || totalBytes+info.Size() > maxDirBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		javaFiles++
		totalBytes += int64(len(data))
		for i, line := range strings.Split(string(data), "\n") {
			if findings >= 100 {
				break
			}
			if !javaExecRe.MatchString(line) && !javaEvalRe.MatchString(line) {
				continue
			}
			findings++
			where := fmt.Sprintf("%s:%d", p, i+1)
			obs.Findings = append(obs.Findings, newFinding(
				"反编译代码中的危险 API 调用",
				"low", "dangerous-call", where,
				fmt.Sprintf("jadx 反编译输出中出现危险 API(%s);参数来源需人工确认,这是启发式符号匹配。",
					clipString(strings.TrimSpace(line), 80)),
				evidenceWithLocation(where, map[string]any{
					"path":      p,
					"artifact":  sourceArtifact,
					"backend":   backend,
					"line":      i + 1,
					"source":    "external-backend:" + backend,
					"heuristic": true,
				}),
				[]string{"binary", "disasm", "mobile", "tier1"},
				[]string{"artifact:" + sourceArtifact},
			))
		}
		return nil
	})
	if walkErr != nil {
		return ledger.Observation{}, javaFiles, walkErr
	}
	return obs, javaFiles, nil
}

// runnableExecutable refuses batch/script wrappers: this package never starts a
// shell, and on Windows CreateProcess cannot launch .bat directly anyway.
func runnableExecutable(path string) (string, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".ps1", ".sh", ".py", ".vbs", ".js":
		return path, false
	}
	return path, true
}
