package binary

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"youkai/internal/ledger"
)

// writeGeneratedText stores a skeleton under ArtifactDir and builds the fact
// for it. The text itself never enters the ledger; only its path and digest do.
func writeGeneratedText(env *Env, capability, text string) (string, ledger.FactSeed, error) {
	name := fmt.Sprintf("%s-%d.txt", capability, time.Now().UnixNano())
	path, err := writeArtifact(env, name, []byte(text))
	if err != nil {
		return "", ledger.FactSeed{}, err
	}
	statement := fmt.Sprintf("%s: 已生成文本骨架 %s(%d 字节),未执行、未发送;需人工审阅", capability, path, len(text))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":           path,
		"capability":     capability,
		"bytes":          len(text),
		"sha256":         sha256Bytes([]byte(text)),
		"executed":       false,
		"sent":           false,
		"text_in_ledger": false,
		"source":         "native-template-generator",
		"note":           "只生成文本骨架;youkai 从不执行或发送它",
	})
	return path, newFact(statement, evidence,
		[]string{"binary", "proof", "skeleton", "tier2"}, nil), nil
}

// templateToken keeps user-supplied values safe to embed in a text skeleton:
// letters, digits, and a small punctuation set only.
func templateToken(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		switch r {
		case '.', '_', '-', '/', ':', '@', ' ', '+':
			b.WriteRune(r)
		}
	}
	out := clipString(strings.TrimSpace(b.String()), 120)
	if out == "" {
		return fallback
	}
	return out
}

// pwnTemplateCapability writes a pwntools skeleton. Tier 2: text only.
func pwnTemplateCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	binaryName := templateToken(argString(args, "binary"), "<BINARY>")
	arch := templateToken(argString(args, "arch"), "amd64")
	remote := templateToken(argString(args, "remote"), "<HOST>:<PORT>")
	text := fmt.Sprintf(`#!/usr/bin/env python3
# youkai pwn_template — SKELETON ONLY.
# youkai does NOT execute this file and never sends payloads.
# Review it, then run it yourself only against an authorised target
# (CTF challenge / your own lab).
from pwn import *

context.binary = elf = ELF(%q, checksec=False)
context.arch = %q
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote(%q)
    return process(elf.path)

io = start()
# 1) leak / find the offset (pwn_cyclic + gdb), confirm protections with checksec
# 2) build the payload
# 3) io.sendline(payload)
# io.interactive()
`, binaryName, arch, remote)
	path, fact, err := writeGeneratedText(env, "pwn_template", text)
	if err != nil {
		return ledger.Observation{}, err
	}
	return ledger.Observation{
		Facts:   []ledger.FactSeed{fact},
		Summary: fmt.Sprintf("pwn_template 骨架 → %s(未执行)", path),
	}, nil
}

// pwnGDBScriptCapability writes a gdb command skeleton. Tier 2: text only.
func pwnGDBScriptCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	binaryName := templateToken(argString(args, "binary"), "<BINARY>")
	text := fmt.Sprintf(`# youkai pwn_gdbscript — SKELETON ONLY, never executed by youkai.
set pagination off
set confirm off
set disassembly-flavor intel
# file %s
break main
run
# pwndbg / gef provide: checksec, vmmap, telescope, heap
# info registers
# x/40gx $rsp
# bt
`, binaryName)
	path, fact, err := writeGeneratedText(env, "pwn_gdbscript", text)
	if err != nil {
		return ledger.Observation{}, err
	}
	return ledger.Observation{
		Facts:   []ledger.FactSeed{fact},
		Summary: fmt.Sprintf("pwn_gdbscript 骨架 → %s(未执行)", path),
	}, nil
}

// impactProofCapability writes a minimal verification-plan skeleton. It never
// performs any of the steps it describes.
func impactProofCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	vulnClass := templateToken(argString(args, "vuln_class"), "<VULN_CLASS>")
	text := fmt.Sprintf(`# youkai impact_proof — SKELETON ONLY
# 漏洞类:%s
# youkai 只生成文本,不发请求、不执行任何步骤。
#
# 0. 授权:确认目标在你被授权的范围内(CTF/自建实验室/书面授权)。
# 1. 最小影响:只证明"影响成立"所需的最小一步,不扩大。
# 2. 数据安全:越权演示只用你自己的两个账号;带外只打你自己的 canary。
# 3. 取证:请求/响应(canary 侧日志)、时间戳、账号归属标记。
# 4. 停止点:证到影响成立的第一刻停止,不 dump 数据、不横向移动。
# 5. 报告:写清授权依据、最小复现、证据位置。
`, vulnClass)
	path, fact, err := writeGeneratedText(env, "impact_proof", text)
	if err != nil {
		return ledger.Observation{}, err
	}
	return ledger.Observation{
		Facts:   []ledger.FactSeed{fact},
		Summary: fmt.Sprintf("impact_proof 方案骨架 → %s(未执行)", path),
	}, nil
}

// fridaScriptCapability writes a Frida skeleton. It never attaches or injects.
func fridaScriptCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	target := templateToken(argString(args, "target"), "<PACKAGE>")
	text := fmt.Sprintf(`// youkai frida_script — SKELETON ONLY.
// youkai does NOT attach to a process, inject code, or execute the target.
// Run it yourself only against an app you own or are authorised to test.
Java.perform(function () {
  // var Target = Java.use(%q);
  // Target.<method>.implementation = function () {
  //   console.log("[youkai] hit", arguments);
  //   return this.<method>.apply(this, arguments);
  // };
});
`, target+".<Class>")
	path, fact, err := writeGeneratedText(env, "frida_script", text)
	if err != nil {
		return ledger.Observation{}, err
	}
	return ledger.Observation{
		Facts:   []ledger.FactSeed{fact},
		Summary: fmt.Sprintf("frida_script 骨架 → %s(未执行/未注入)", path),
	}, nil
}

// webPoCCapability writes an HTTP request skeleton. No request is ever sent.
func webPoCCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL := templateToken(argString(args, "url"), "<URL>")
	method := strings.ToUpper(templateToken(argString(args, "method"), "GET"))
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD":
	default:
		method = "GET"
	}
	body := ""
	if method != "GET" && method != "HEAD" {
		body = "Content-Type: application/json\n\n{\"probe\": \"youkai-canary\"}\n"
	}
	text := fmt.Sprintf(`# youkai web_poc — SKELETON ONLY. No request has been sent.
# Review it, then send it yourself only inside an authorised scope.
%s %s HTTP/1.1
Host: %s
User-Agent: youkai-poc/0.2
Accept: */*
%s`, method, rawURL, "<HOST-FROM-URL>", body)
	path, fact, err := writeGeneratedText(env, "web_poc", text)
	if err != nil {
		return ledger.Observation{}, err
	}
	return ledger.Observation{
		Facts:   []ledger.FactSeed{fact},
		Summary: fmt.Sprintf("web_poc 骨架 → %s(未发送)", path),
	}, nil
}

// downloadCapability is registered at tier 2 but deliberately does nothing:
// fetching attacker-controlled bytes is a human decision and must go through
// discipline.Guard, which this package does not import.
func downloadCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	return ledger.Observation{}, fmt.Errorf(
		"%w: downloading goes through discipline.Guard and requires a human confirm; this package has no network capability",
		ErrNotImplemented)
}
