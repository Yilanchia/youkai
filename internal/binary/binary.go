// Package binary is youkai's read-only static analysis of artifacts: native
// executables, mobile packages, firmware images, and source trees, together
// with their strings, protections, symbols, and leaked secrets.
//
// The contract is deliberately narrow. Everything here is offline: no HTTP
// client, no network, no execution of the analysed sample. The only processes
// this package ever starts are whitelisted analysis tools (objdump, nm,
// readelf, jadx, Ghidra) with explicit argv, a hard context timeout, and
// capped output. Writes happen only inside Env.ArtifactDir after a
// resolved-path prefix check.
//
// Every capability returns ledger seeds only: facts, candidate findings, and
// assets. It cannot mark anything verified. Missing backends and unparsable
// files are reported as such; this package never fabricates a result.
package binary

import (
	"context"
	"errors"
	"fmt"

	"youkai/internal/gate"
	"youkai/internal/ledger"
)

// Env is the per-engagement context a capability runs under.
type Env struct {
	// ArtifactDir is the isolated directory where registered samples live.
	ArtifactDir  string
	EngagementID int64
	Engagement   string
}

// Capability is one typed, bounded analysis action.
type Capability struct {
	Name        string
	Description string
	Tier        gate.Tier
	Run         func(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error)
}

// Sentinel errors. Callers use errors.Is to tell "tool missing" from "refused".
var (
	// ErrUnavailable means the file cannot be analysed with the backends this
	// build has: no objdump/nm/readelf/jadx/Ghidra, or a format the native
	// parsers do not cover. It never means "assume insecure".
	ErrUnavailable = errors.New("binary: analysis backend unavailable")
	// ErrRefused means the request violated the package's safety rules: path
	// traversal, a symlink, a file over the size cap, a missing ArtifactDir.
	ErrRefused = errors.New("binary: refused")
	// ErrNotImplemented means the capability is registered (its tier is real)
	// but this build deliberately does not perform the action.
	ErrNotImplemented = errors.New("binary: not implemented")
)

// registry is the single source of truth for what this package offers. The
// order is the order the UI and prompts present.
var registry = []Capability{
	{
		Name: "binflow",
		Description: "Pair an input point (argv/recv/read/getenv) with a dangerous call (system/exec/strcpy/sprintf/printf) " +
			"and emit code-only hypotheses. Static symbols only: no execution, no emulation, exploitability stays human. | " +
			"中文:输入点→危险调用的符号级可达性,产出 code-only 线索;不执行、不模拟,可利用性交人工。",
		Tier: gate.TierReadOnly,
		Run:  binflowCapability,
	},
	{
		Name: "blind_screen",
		Description: "Measure whether a sample was built to mislead an analyser: poisoned strings, noise volume, " +
			"anti-debug vocabulary, packer signatures, entropy. Emits a confidence label (clean / suspected-blinded / " +
			"heavily-blinded) and never executes, unpacks or judges exploitability. | " +
			"中文:识别样本是否被 AI 逆向对抗处理(投毒/噪声/反调试/加壳),给可信度标签;不执行、不脱壳、不判可利用性。",
		Tier: gate.TierReadOnly,
		Run:  blindScreen,
	},
	{
		Name:        "artifact_identify",
		Description: "Identify an artifact by magic bytes (PE/ELF/Mach-O/APK/ZIP/DEX/WASM/Java/firmware) and record sha256. Read-only, never executes the sample. | 中文:按魔数识别样本格式并记录 sha256,只读不执行。",
		Tier:        gate.TierReadOnly,
		Run:         identifyCapability,
	},
	{
		Name:        "artifact_register",
		Description: "Hash a sample and copy it into the isolated ArtifactDir (no execution, no network). | 中文:计算 sha256 并复制进隔离样本目录,不执行不联网。",
		Tier:        gate.TierReadOnly,
		Run:         registerCapability,
	},
	{
		Name:        "strings",
		Description: "Extract bounded printable ASCII and UTF-16LE strings; classify URLs, paths, and credential-ish keywords with redacted samples. | 中文:提取可打印字符串并分类,样例一律脱敏。",
		Tier:        gate.TierReadOnly,
		Run:         stringsCapability,
	},
	{
		Name:        "checksec",
		Description: "Native ELF/PE parsers report PIE, NX, RELRO, canary, DEP, ASLR, CFG from parsed structure; unknowns stay unknown. | 中文:原生解析 ELF/PE 保护机制,无法判定就写 unknown。",
		Tier:        gate.TierReadOnly,
		Run:         checksecCapability,
	},
	{
		Name:        "symbols",
		Description: "List symbols/imports via nm/readelf/objdump when present and flag dangerous imports; reports the missing backend instead of guessing. | 中文:用可用后端列符号并标记危险导入,缺后端就如实说明。",
		Tier:        gate.TierReadOnly,
		Run:         symbolsCapability,
	},
	{
		Name:        "disasm",
		Description: "Bounded disassembly via objdump (native) or jadx (APK); dangerous call sites are reported with path:0xaddr. Missing backend is ErrUnavailable. | 中文:objdump/jadx 有界反汇编,缺后端明确报错。",
		Tier:        gate.TierReadOnly,
		Run:         disasmCapability,
	},
	{
		Name:        "decompile",
		Description: "Bounded decompilation via jadx (APK/DEX) or Ghidra (VERDEX_GHIDRA); never executes the sample. Missing backend is ErrUnavailable. | 中文:jadx/Ghidra 有界反编译,缺后端明确报错。",
		Tier:        gate.TierReadOnly,
		Run:         decompileCapability,
	},
	{
		Name:        "mobile_unpack",
		Description: "Inventory an APK as a ZIP: manifest, dex files, native libs, assets; extracts only inside ArtifactDir when asked. | 中文:纯 Go 清点 APK 结构,只在样本目录内按需解包。",
		Tier:        gate.TierReadOnly,
		Run:         mobileUnpackCapability,
	},
	{
		Name:        "firmware_extract",
		Description: "Detect firmware containers (squashfs/cramfs/gzip/xz/UBI/TRX/...) by signature; extraction needs external tools and is reported as unavailable, never faked. | 中文:按签名检测固件容器,缺解包工具就如实降级。",
		Tier:        gate.TierReadOnly,
		Run:         firmwareCapability,
	},
	{
		Name:        "secrets",
		Description: "Regex sweep for cloud keys, private keys, JWTs, tokens, password assignments, and connection strings; only masked previews leave the file. | 中文:扫描硬编码凭据,只输出脱敏预览。",
		Tier:        gate.TierReadOnly,
		Run:         secretsCapability,
	},
	{
		Name:        "dataflow",
		Description: "Heuristic source-to-sink reachability over C/C++/Java/JS source, reported as candidates with file:line and an explicit heuristic note. | 中文:源码 source→sink 启发式可达性,候选结论并注明启发式。",
		Tier:        gate.TierReadOnly,
		Run:         dataflowCapability,
	},
	{
		Name:        "sarif",
		Description: "Convert a JSON findings array into a minimal valid SARIF 2.1.0 document under ArtifactDir. | 中文:把 JSON findings 转成最小合法 SARIF 2.1.0。",
		Tier:        gate.TierReadOnly,
		Run:         sarifCapability,
	},
	{
		Name:        "doctor",
		Description: "Probe optional analysis backends and say exactly what degrades when one is missing. | 中文:预检可选后端,缺失即说明降级影响。",
		Tier:        gate.TierReadOnly,
		Run:         doctorCapability,
	},
	{
		Name:        "pwn_template",
		Description: "Write a minimal pwntools exploit skeleton to ArtifactDir. Text only: never executed, never sent. | 中文:只生成 pwntools 骨架文本,不执行不发送。",
		Tier:        gate.TierProof,
		Run:         pwnTemplateCapability,
	},
	{
		Name:        "pwn_gdbscript",
		Description: "Write a minimal gdb script skeleton to ArtifactDir. Text only: never executed. | 中文:只生成 gdb 脚本骨架,不执行。",
		Tier:        gate.TierProof,
		Run:         pwnGDBScriptCapability,
	},
	{
		Name:        "impact_proof",
		Description: "Write a minimal impact-verification plan skeleton (text) for one vuln class to ArtifactDir. Never runs the steps. | 中文:生成最小影响验证方案骨架,不执行任何步骤。",
		Tier:        gate.TierProof,
		Run:         impactProofCapability,
	},
	{
		Name:        "frida_script",
		Description: "Write a Frida instrumentation skeleton (text) to ArtifactDir. Never executes, never attaches. | 中文:生成 Frida 脚本骨架,不执行不注入。",
		Tier:        gate.TierProof,
		Run:         fridaScriptCapability,
	},
	{
		Name:        "web_poc",
		Description: "Write an HTTP PoC request skeleton (text) to ArtifactDir. Never sends a request. | 中文:生成 HTTP PoC 请求骨架,不发送请求。",
		Tier:        gate.TierProof,
		Run:         webPoCCapability,
	},
	{
		Name:        "download",
		Description: "Registered tier 2, but downloading must go through discipline.Guard with a human confirm; this package has no network and refuses. | 中文:下载必须走 discipline.Guard 且需人工确认,本包不联网,直接拒绝。",
		Tier:        gate.TierProof,
		Run:         downloadCapability,
	},
}

var capabilityIndex = func() map[string]Capability {
	m := make(map[string]Capability, len(registry))
	for _, c := range registry {
		m[c.Name] = c
	}
	return m
}()

// Registry returns every capability this package implements, in stable order.
func Registry() []Capability {
	out := make([]Capability, len(registry))
	copy(out, registry)
	return out
}

// Lookup resolves one capability by its gate-registered name.
func Lookup(name string) (Capability, bool) {
	c, ok := capabilityIndex[name]
	return c, ok
}

// Run dispatches a capability by name after the caller (the gate) has decided
// the tier. It refuses unknown names and a nil env rather than panicking.
func Run(ctx context.Context, env *Env, name string, args map[string]any) (ledger.Observation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	capability, ok := Lookup(name)
	if !ok {
		return ledger.Observation{}, fmt.Errorf("%w: unknown capability %q", ErrRefused, name)
	}
	if env == nil {
		return ledger.Observation{}, fmt.Errorf("%w: %s requires an Env", ErrRefused, capability.Name)
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	obs, err := capability.Run(ctx, env, args)
	if err != nil {
		return obs, fmt.Errorf("binary: %s: %w", capability.Name, err)
	}
	return obs, nil
}
