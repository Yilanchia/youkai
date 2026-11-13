package binary

import (
	"context"
	"fmt"
	"os"

	"youkai/internal/ledger"
)

// checksecCapability reports exploit mitigations from native structure parsing.
// It never calls readelf/objdump, so its answer does not depend on a backend
// being installed; whatever cannot be parsed is reported as unknown.
func checksecCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, _, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	fi, err := sniffFormat(path, fileSize(path))
	if err != nil {
		return ledger.Observation{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 读取 %s: %v", ErrRefused, path, err)
	}

	switch fi.Format {
	case "ELF":
		return checksecELF(path, data)
	case "PE":
		return checksecPE(path, data)
	default:
		return ledger.Observation{}, fmt.Errorf(
			"%w: checksec 仅原生支持 ELF/PE,该文件是 %s;Mach-O 等格式需要外部后端,未执行、未猜测",
			ErrUnavailable, fi.Format)
	}
}

func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func checksecELF(path string, data []byte) (ledger.Observation, error) {
	prot, err := parseELF(data)
	if err != nil {
		return ledger.Observation{}, err
	}
	statement := fmt.Sprintf("checksec:elf pie=%t nx=%t relro=%s canary=%s",
		prot.PIE, prot.NX, prot.RELRO, prot.Canary)
	evidence := evidenceWithLocation(path, map[string]any{
		"path":         path,
		"format":       "elf",
		"source":       "native-elf-parser",
		"class":        prot.Class,
		"endian":       prot.Endian,
		"type":         prot.Type,
		"machine":      prot.Machine,
		"pie":          prot.PIE,
		"nx":           prot.NX,
		"relro":        prot.RELRO,
		"canary":       prot.Canary,
		"fortify":      prot.Fortify,
		"dynamic":      prot.Dynamic,
		"parsed":       []string{"e_ident/e_type/e_machine", "program headers", "dynamic segment"},
		"undetermined": []string{"canary", "fortify"},
		"notes":        prot.Notes,
	})
	obs := ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "checksec", "elf", "tier1"}, []string{"artifact:" + path})},
		Summary: statement,
	}
	if prot.Type != "EXEC" && prot.Type != "DYN" {
		// Object/core files have no exploit mitigations to be missing.
		return obs, nil
	}
	return addELFHardeningFindings(obs, path, prot), nil
}

func addELFHardeningFindings(obs ledger.Observation, path string, prot *elfProtections) ledger.Observation {
	detailSuffix := "由本包直接解析 ELF 程序头/动态段/节头得出;canary=" + prot.Canary +
		"(需要符号表),fortify=" + prot.Fortify + "。"
	add := func(title, severity, detail string, extra map[string]any) {
		ev := evidenceWithLocation(path, map[string]any{
			"path":   path,
			"format": "elf",
			"source": "native-elf-parser",
		})
		for k, v := range extra {
			ev[k] = v
		}
		obs.Findings = append(obs.Findings, newFinding(title, severity, "hardening", path,
			detail+" "+detailSuffix, ev,
			[]string{"binary", "checksec", "hardening"}, []string{"artifact:" + path}))
	}
	if !prot.NX {
		add("ELF 未启用 NX(栈可执行)", "low",
			"PT_GNU_STACK 存在且带执行位(PF_X),栈可执行。", map[string]any{"missing": "nx"})
	}
	if prot.RELRO == "none" {
		add("ELF 未启用 RELRO", "low",
			"未找到 PT_GNU_RELRO 程序头,GOT 可被部分改写。", map[string]any{"missing": "relro"})
	}
	if prot.Canary == "no" {
		add("ELF 未启用栈 canary", "low",
			"符号表中没有 __stack_chk_fail/__stack_chk_guard,判定未启用 canary。",
			map[string]any{"missing": "canary"})
	}
	if !prot.PIE {
		add("ELF 不是 PIE", "info",
			"e_type 不是 ET_DYN(报告为 EXEC),配合 ASLR 的地址随机化弱。",
			map[string]any{"missing": "pie"})
	}
	return obs
}

func checksecPE(path string, data []byte) (ledger.Observation, error) {
	prot, err := parsePE(data)
	if err != nil {
		return ledger.Observation{}, err
	}
	// RELRO is an ELF concept; PE has no equivalent, so it is reported as n/a
	// rather than "none", which would imply a missing mitigation.
	statement := fmt.Sprintf("checksec:pe pie=%t nx=%t relro=n/a canary=%s",
		prot.ASLR, prot.NX, prot.Canary)
	evidence := evidenceWithLocation(path, map[string]any{
		"path":                path,
		"format":              "pe",
		"source":              "native-pe-parser",
		"machine":             prot.Machine,
		"bitness":             prot.Bitness,
		"dll_characteristics": fmt.Sprintf("0x%04x", prot.DllCharacteristics),
		"pie":                 prot.ASLR,
		"nx":                  prot.NX,
		"relro":               "n/a",
		"aslr":                prot.ASLR,
		"high_entropy_va":     prot.HighEntropyVA,
		"dep":                 prot.NX,
		"cfg":                 prot.CFG,
		"force_integrity":     prot.ForceIntegrity,
		"seh":                 prot.SEH,
		"canary":              prot.Canary,
		"parsed":              []string{"DOS header", "NT signature", "COFF header", "optional header DllCharacteristics"},
		"undetermined":        []string{"seh", "canary"},
		"notes":               prot.Notes,
	})
	obs := ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "checksec", "pe", "tier1"}, []string{"artifact:" + path})},
		Summary: statement,
	}
	detailSuffix := fmt.Sprintf("由本包直接解析 PE 可选头 DllCharacteristics=0x%04x 得出;SEH/canary 无 load config/符号表,报 unknown。", prot.DllCharacteristics)
	add := func(title, severity, detail string, extra map[string]any) {
		ev := evidenceWithLocation(path, map[string]any{
			"path":   path,
			"format": "pe",
			"source": "native-pe-parser",
		})
		for k, v := range extra {
			ev[k] = v
		}
		obs.Findings = append(obs.Findings, newFinding(title, severity, "hardening", path,
			detail+" "+detailSuffix, ev,
			[]string{"binary", "checksec", "hardening"}, []string{"artifact:" + path}))
	}
	if !prot.ASLR {
		add("PE 未启用 ASLR(DYNAMIC_BASE)", "low",
			"DllCharacteristics 未设置 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE(0x0040)。",
			map[string]any{"missing": "aslr"})
	}
	if !prot.NX {
		add("PE 未启用 DEP/NX(NX_COMPAT)", "low",
			"DllCharacteristics 未设置 IMAGE_DLLCHARACTERISTICS_NX_COMPAT(0x0100)。",
			map[string]any{"missing": "dep"})
	}
	if !prot.CFG {
		add("PE 未启用控制流防护(CFG)", "info",
			"DllCharacteristics 未设置 IMAGE_DLLCHARACTERISTICS_GUARD_CF(0x4000)。",
			map[string]any{"missing": "cfg"})
	}
	if !prot.ForceIntegrity {
		obs.Findings = append(obs.Findings, newFinding(
			"PE 未强制签名校验(FORCE_INTEGRITY)",
			"info", "hardening", path,
			"DllCharacteristics 未设置 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY(0x0080)。 "+detailSuffix,
			evidenceWithLocation(path, map[string]any{
				"path": path, "format": "pe", "source": "native-pe-parser", "missing": "force-integrity",
			}),
			[]string{"binary", "checksec", "hardening"}, []string{"artifact:" + path}))
	}
	return obs, nil
}
