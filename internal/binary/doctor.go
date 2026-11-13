package binary

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"youkai/internal/ledger"
)

// doctorBackend describes one optional backend and what degrades without it.
type doctorBackend struct {
	ID       string
	Label    string
	EnvVar   string
	Degrades string
	Hint     string
}

var doctorBackends = []doctorBackend{
	{
		ID: "objdump", Label: "objdump (binutils)", Degrades: "disasm、symbols(第三后端)",
		Hint: "安装 binutils 并加入 PATH;缺少时 disasm 直接报 ErrUnavailable。",
	},
	{
		ID: "readelf", Label: "readelf (binutils)", Degrades: "symbols(第二后端)、ELF 符号表补充",
		Hint: "安装 binutils;checksec 不依赖它(本包原生解析 ELF)。",
	},
	{
		ID: "nm", Label: "nm (binutils)", Degrades: "symbols 首选后端",
		Hint: "安装 binutils;缺少时 symbols 依次退到 readelf/objdump。",
	},
	{
		ID: "jadx", Label: "jadx (DEX→Java)", EnvVar: "VERDEX_JADX", Degrades: "APK/DEX 的 disasm、decompile",
		Hint: "安装 jadx 或设置 VERDEX_JADX 指向可执行入口(不接受 .bat 包装,本包不启 shell)。",
	},
	{
		ID: "ghidra", Label: "Ghidra headless", EnvVar: "VERDEX_GHIDRA", Degrades: "原生 ELF/PE/Mach-O 的 decompile",
		Hint: "设置 VERDEX_GHIDRA 指向 analyzeHeadless(或 Ghidra 安装目录),并安装 JDK 21+;不接受 .bat 包装。",
	},
}

// doctorCapability probes the machine for optional analysis backends and says
// exactly what will degrade. It never touches an artifact and never runs one.
func doctorCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	backends := make([]map[string]any, 0, len(doctorBackends))
	available := []string{}
	missing := []string{}
	degraded := []string{}
	nextSteps := []string{}

	for _, b := range doctorBackends {
		var (
			path string
			ok   bool
		)
		if b.ID == "ghidra" {
			path, ok = findGhidraHeadless()
		} else {
			path, ok = findTool(b.ID, b.EnvVar)
		}
		entry := map[string]any{
			"id":      b.ID,
			"label":   b.Label,
			"env":     b.EnvVar,
			"affects": b.Degrades,
			"status":  "missing",
		}
		if ok {
			entry["path"] = path
			if _, runnable := runnableExecutable(path); !runnable {
				entry["status"] = "present-but-not-runnable"
				entry["detail"] = "批处理/脚本包装;本包不以 shell 方式运行"
				missing = append(missing, b.ID)
				degraded = append(degraded, b.Degrades)
				nextSteps = append(nextSteps, b.ID+": "+b.Hint)
			} else {
				entry["status"] = "ok"
				entry["version"] = probeVersion(ctx, path)
				available = append(available, b.ID+"("+path+")")
			}
		} else {
			entry["detail"] = "未在 PATH 或环境变量中找到"
			missing = append(missing, b.ID)
			degraded = append(degraded, b.Degrades)
			nextSteps = append(nextSteps, b.ID+": "+b.Hint)
		}
		backends = append(backends, entry)
	}

	// checksec, secrets, strings, dataflow, mobile_unpack, firmware detection and
	// sarif are native and never depend on these backends.
	statement := fmt.Sprintf(
		"doctor: 本机 %s(%s/%s) 分析后端 ok=%d missing=%d;可用=%s;缺失将降级=%s",
		host, runtime.GOOS, runtime.GOARCH, len(available), len(missing),
		joinOrNone(available), joinOrNone(degraded))
	evidence := evidenceWithLocation("host:"+host, map[string]any{
		"host":        host,
		"goos":        runtime.GOOS,
		"goarch":      runtime.GOARCH,
		"backends":    backends,
		"available":   available,
		"missing":     missing,
		"degraded":    degraded,
		"next_steps":  nextSteps,
		"native_only": []string{"checksec", "secrets", "strings", "dataflow", "mobile_unpack", "firmware_extract(detection)", "sarif", "artifact_identify", "artifact_register"},
		"executed":    false,
		"source":      "backend-probe",
	})
	return ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "doctor", "backends", "tier1"}, nil)},
		Summary: statement,
	}, nil
}

func joinOrNone(list []string) string {
	if len(list) == 0 {
		return "无"
	}
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
