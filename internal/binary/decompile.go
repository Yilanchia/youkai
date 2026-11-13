package binary

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"youkai/internal/ledger"
)

// ghidraDecompileScript is written into ArtifactDir and handed to Ghidra's
// analyzeHeadless. It decompiles every function into one text file. It is data
// to Ghidra, not a program youkai runs itself.
const ghidraDecompileScript = `// youkai Ghidra post-script: dump decompiled C for every function.
// @category youkai
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;

public class YoukaiDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        String outPath = scriptArgs.length > 0 ? scriptArgs[0] : "youkai-decompile.c";
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        PrintWriter writer = new PrintWriter(outPath, "UTF-8");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int dumped = 0;
        while (functions.hasNext() && dumped < 2000) {
            Function f = functions.next();
            DecompileResults result = ifc.decompileFunction(f, 60, monitor);
            writer.println("// " + f.getName() + " @ " + f.getEntryPoint());
            if (result != null && result.decompileCompleted()) {
                writer.println(result.getDecompiledFunction().getC());
            }
            dumped++;
        }
        writer.close();
        println("youkai: decompiled " + dumped + " functions into " + outPath);
    }
}
`

// decompileCapability produces readable code through jadx (APK/DEX) or Ghidra
// (native, via VERDEX_GHIDRA). Without a backend it returns ErrUnavailable and
// names exactly what to install.
func decompileCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	fi, err := sniffFormat(path, size)
	if err != nil {
		return ledger.Observation{}, err
	}
	switch fi.Format {
	case "APK", "DEX":
		return decompileWithJadx(ctx, env, path, fi.Format)
	case "ELF", "PE", "Mach-O":
		return decompileWithGhidra(ctx, env, path, fi.Format)
	default:
		return ledger.Observation{}, fmt.Errorf(
			"%w: decompile 不支持格式 %s(需要 jadx 或 Ghidra 后端)", ErrUnavailable, fi.Format)
	}
}

func decompileWithJadx(ctx context.Context, env *Env, path, format string) (ledger.Observation, error) {
	outDir, err := runJadx(ctx, env, path, "jadx-decompile")
	if err != nil {
		return ledger.Observation{}, err
	}
	obs, javaFiles, err := scanDecompiledJava(ctx, outDir, path, "jadx")
	if err != nil {
		return ledger.Observation{}, err
	}
	statement := fmt.Sprintf("decompile: %s backend=jadx java 文件=%d 输出目录=%s(未执行样本)",
		path, javaFiles, outDir)
	evidence := evidenceWithLocation(path, map[string]any{
		"path":       path,
		"format":     strings.ToLower(format),
		"backend":    "jadx",
		"output_dir": outDir,
		"java_files": javaFiles,
		"source":     "external-backend:jadx",
		"executed":   false,
	})
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "decompile", "jadx", "tier1"}, []string{"artifact:" + path}))
	obs.Summary = statement
	return obs, nil
}

func decompileWithGhidra(ctx context.Context, env *Env, path, format string) (ledger.Observation, error) {
	headless, found := findGhidraHeadless()
	if !found {
		return ledger.Observation{}, fmt.Errorf(
			"%w: 未配置 Ghidra;设置 VERDEX_GHIDRA 指向 analyzeHeadless(或包含 support/analyzeHeadless 的 Ghidra 目录)", ErrUnavailable)
	}
	if _, runnable := runnableExecutable(headless); !runnable {
		return ledger.Observation{}, fmt.Errorf(
			"%w: Ghidra 入口 %s 是批处理/脚本包装,本包不以 shell 方式运行它", ErrUnavailable, headless)
	}
	if _, ok := findTool("java", ""); !ok {
		return ledger.Observation{}, fmt.Errorf(
			"%w: Ghidra 需要 JDK(未在 PATH 上找到 java);安装 JDK 21+ 后重试", ErrUnavailable)
	}
	dir, err := artifactDir(env)
	if err != nil {
		return ledger.Observation{}, err
	}
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	scriptDir, err := ensureWithin(dir, filepath.Join(dir, "ghidra-scripts"))
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := os.MkdirAll(scriptDir, 0o700); err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 创建 Ghidra 脚本目录: %v", ErrRefused, err)
	}
	scriptPath, err := ensureWithin(scriptDir, filepath.Join(scriptDir, "YoukaiDecompile.java"))
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := os.WriteFile(scriptPath, []byte(ghidraDecompileScript), 0o600); err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 写入 Ghidra 脚本: %v", ErrRefused, err)
	}
	projectDir, err := ensureWithin(dir, filepath.Join(dir, "ghidra-project"))
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 创建 Ghidra 工程目录: %v", ErrRefused, err)
	}
	outPath, err := ensureWithin(dir, filepath.Join(dir, "ghidra-decompile-"+stamp+".c"))
	if err != nil {
		return ledger.Observation{}, err
	}

	argv := []string{
		projectDir, "youkai-" + stamp,
		"-import", path,
		"-postScript", "YoukaiDecompile.java", outPath,
		"-scriptPath", scriptDir,
		"-deleteProject",
		"-analysisTimeoutPerFile", "180",
	}
	_, _, runErr := runTool(ctx, 360*time.Second, headless, argv, 1<<20)
	data, readErr := readBounded(outPath, 8<<20)
	if readErr != nil || len(data) == 0 {
		detail := "Ghidra 未产出反编译文件"
		if runErr != nil {
			detail += ":" + clipString(runErr.Error(), 200)
		} else {
			detail += "(analyzeHeadless 返回成功但没有输出,可能缺少 java 或脚本失败)"
		}
		return ledger.Observation{}, fmt.Errorf("%w: %s", ErrUnavailable, detail)
	}
	statement := fmt.Sprintf("decompile: %s backend=ghidra 输出=%s 大小=%d(未执行样本)", path, outPath, len(data))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":        path,
		"format":      strings.ToLower(format),
		"backend":     "ghidra",
		"output":      outPath,
		"output_size": len(data),
		"source":      "external-backend:ghidra",
		"executed":    false,
	})
	if runErr != nil {
		evidence["backend_warning"] = clipString(runErr.Error(), 300)
	}
	obs := ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "decompile", "ghidra", "tier1"}, []string{"artifact:" + path})},
		Summary: statement,
	}
	return obs, nil
}

// findGhidraHeadless resolves VERDEX_GHIDRA, accepting either the headless
// launcher itself or the Ghidra install directory.
func findGhidraHeadless() (string, bool) {
	raw := strings.TrimSpace(os.Getenv("VERDEX_GHIDRA"))
	if raw == "" {
		return "", false
	}
	if info, err := os.Stat(raw); err == nil {
		if info.IsDir() {
			for _, name := range []string{
				filepath.Join("support", "analyzeHeadless"),
				filepath.Join("support", "analyzeHeadless.bat"),
				filepath.Join("support", "analyzeHeadless.sh"),
			} {
				candidate := filepath.Join(raw, name)
				if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
					return candidate, true
				}
			}
			return "", false
		}
		return raw, true
	}
	if p, ok := findTool(raw, ""); ok {
		return p, true
	}
	return "", false
}
