// Package hands wires the two hands - Fairy (web) and Verdex (binary) - into the
// loop's Hands interface, and owns the web->binary handoff.
//
// Nothing here sends a target request on its own: every call is a hand call, and
// the hand re-checks its own authorisation. youkai's contribution is routing and
// framing, not capability.
package hands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"youkai/internal/mcp"
)

// Logical hand names.
const (
	Fairy  = "fairy"
	Verdex = "verdex"
)

// Config is .youkai/hands.json: how to launch each hand.
type Config struct {
	Fairy  mcp.HandConfig `json:"fairy"`
	Verdex mcp.HandConfig `json:"verdex"`
}

// DefaultConfigPath is the conventional location, relative to the workspace root.
const DefaultConfigPath = ".youkai/hands.json"

// LoadConfig reads hands.json.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.Fairy.Name = Fairy
	cfg.Verdex.Name = Verdex
	return cfg, nil
}

// SaveConfig writes hands.json, creating the directory.
func SaveConfig(path string, cfg Config) error {
	cfg.Fairy.Name = ""
	cfg.Verdex.Name = ""
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Configured reports whether a hand entry looks launchable.
func (c Config) Configured() (fairy, verdex bool) {
	fairy = strings.TrimSpace(c.Fairy.Cmd) != "" && strings.TrimSpace(c.Fairy.Cwd) != ""
	verdex = strings.TrimSpace(c.Verdex.Cmd) != "" && strings.TrimSpace(c.Verdex.Cwd) != ""
	return
}

// ---- tool ownership --------------------------------------------------------

// cannonicalises the design doc's spellings onto the hands' real tool names.
var aliases = map[string]string{
	"fairy_probe":   "web_probe",
	"fairy_scan":    "web_scan",
	"fairy_compare": "web_compare",
}

// Canonical maps a documented alias to the real tool name.
func Canonical(tool string) string {
	if c, ok := aliases[tool]; ok {
		return c
	}
	return tool
}

// verdexOnly are Verdex tools whose names would otherwise look like Fairy's.
var verdexOnly = map[string]bool{
	"web_recon":      true,
	"web_poc":        true,
	"har_analyze":    true,
	"analyze_target": true,
}

// OwnerByPrefix is the offline routing rule, used when a hand cannot be asked.
// It is a heuristic; the advertised tool set always wins when available.
func OwnerByPrefix(tool string) (string, bool) {
	tool = Canonical(tool)
	if verdexOnly[tool] {
		return Verdex, true
	}
	switch {
	case strings.HasPrefix(tool, "fairy_"),
		strings.HasPrefix(tool, "web_"),
		tool == "har_ingest":
		return Fairy, true
	}
	if verdexCatalog[tool] {
		return Verdex, true
	}
	return "", false
}

var verdexCatalog = map[string]bool{
	"assets": true, "map": true, "scan": true, "osint": true, "report": true,
	"diff": true, "explain": true, "bin_dossier": true, "bin_info": true,
	"bin_symbols": true, "bin_strings": true, "bin_disasm": true,
	"bin_decompile": true, "reconstruct": true, "har_analyze": true,
	"web_recon": true, "web_poc": true, "dex_decompile": true,
	"wxapkg_unpack": true, "mobile_unpack": true, "secrets": true,
	"fw_extract": true, "fw_scan": true, "js_deobfuscate": true,
	"analyze_target": true, "frida_script": true, "dotnet_decompile": true,
	"asar_unpack": true, "impact_proof": true, "pwn_checksec": true,
	"pwn_gadgets": true, "pwn_template": true, "pwn_cyclic": true,
	"pwn_gdbscript": true, "pwn_libc": true,
}
