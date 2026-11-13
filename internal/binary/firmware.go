package binary

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"

	"youkai/internal/ledger"
)

// firmwareSig is one container/compression signature. It describes what was
// found and which external tool would be needed to go further; this package
// never invokes those extraction tools.
type firmwareSig struct {
	Name  string
	Magic []byte
	Tool  string
	Weak  bool
}

var firmwareSigs = []firmwareSig{
	{Name: "SquashFS (little-endian)", Magic: []byte("hsqs"), Tool: "unsquashfs / sasquatch"},
	{Name: "SquashFS (big-endian)", Magic: []byte("sqsh"), Tool: "unsquashfs"},
	{Name: "CramFS", Magic: []byte{0x28, 0xcd, 0x3d, 0x45}, Tool: "cramfsck / uncramfs"},
	{Name: "UBI image (UBI#)", Magic: []byte("UBI#"), Tool: "ubireader_extract_images"},
	{Name: "UBIFS", Magic: []byte{0x31, 0x18, 0x10, 0x06}, Tool: "ubireader_extract_files"},
	{Name: "U-Boot uImage header", Magic: []byte{0x27, 0x05, 0x19, 0x56}, Tool: "dumpimage / binwalk"},
	{Name: "TRX firmware (HDR0)", Magic: []byte("HDR0"), Tool: "binwalk / trx tools"},
	{Name: "Flattened Device Tree (DTB)", Magic: []byte{0xd0, 0x0d, 0xfe, 0xed}, Tool: "dtc -I dtb"},
	{Name: "Android boot image", Magic: []byte("ANDROID!"), Tool: "unpack_bootimg / abootimg"},
	{Name: "cpio archive (ascii)", Magic: []byte("0707"), Tool: "cpio -idv"},
	{Name: "gzip stream", Magic: []byte{0x1f, 0x8b, 0x08}, Tool: "gunzip"},
	{Name: "ZIP wrapper", Magic: []byte("PK\x03\x04"), Tool: "unzip"},
	{Name: "xz stream", Magic: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, Tool: "unxz"},
	{Name: "bzip2 stream", Magic: []byte{'B', 'Z', 'h'}, Tool: "bunzip2"},
	{Name: "LZO stream", Magic: []byte{0x89, 'L', 'Z', 'O'}, Tool: "lzop -d"},
	{Name: "LZMA stream (heuristic)", Magic: []byte{0x5d, 0x00, 0x00}, Tool: "unlzma", Weak: true},
}

// detectFirmwareContainer returns the first known container name found in the
// head bytes, or "".
func detectFirmwareContainer(head []byte) string {
	for _, sig := range firmwareSigs {
		if bytes.Contains(head, sig.Magic) {
			return sig.Name
		}
	}
	return ""
}

// firmwareCapability detects containers and reports exactly which extraction
// backend a human would need. It writes nothing and runs no extractor.
func firmwareCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 读取 %s: %v", ErrRefused, path, err)
	}

	type hit struct {
		Offset int
		Name   string
		Tool   string
		Weak   bool
	}
	var hits []hit
	perSig := map[string]int{}
	for _, sig := range firmwareSigs {
		from := 0
		for len(hits) < 500 && perSig[sig.Name] < 50 {
			idx := bytes.Index(data[from:], sig.Magic)
			if idx < 0 {
				break
			}
			off := from + idx
			hits = append(hits, hit{Offset: off, Name: sig.Name, Tool: sig.Tool, Weak: sig.Weak})
			perSig[sig.Name]++
			from = off + len(sig.Magic)
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Offset < hits[j].Offset })
	hitMaps := make([]map[string]any, 0, len(hits))
	tools := map[string]bool{}
	for _, h := range hits {
		hitMaps = append(hitMaps, map[string]any{
			"offset":       h.Offset,
			"offset_hex":   fmt.Sprintf("0x%x", h.Offset),
			"type":         h.Name,
			"extract_with": h.Tool,
			"weak":         h.Weak,
		})
		tools[h.Tool] = true
	}

	obs := ledger.Observation{}
	statement := fmt.Sprintf("firmware_extract: %s 特征命中 %d 处(只做检测,未解包、未写入文件)", path, len(hits))
	if len(hits) == 0 {
		statement = fmt.Sprintf("firmware_extract: %s 未识别到已知固件容器(可能加密或未知格式;未解包、未写入文件)", path)
	}
	evidence := evidenceWithLocation(path, map[string]any{
		"path":         path,
		"size":         size,
		"signatures":   hitMaps,
		"hit_count":    len(hits),
		"source":       "native-signature-scan",
		"extracted":    false,
		"executed":     false,
		"artifact_dir": env.ArtifactDir,
	})
	obs.Facts = append(obs.Facts, newFact(statement, evidence,
		[]string{"binary", "firmware", "tier1"}, []string{"artifact:" + path}))

	backendStatement := fmt.Sprintf(
		"firmware_extract: 解包后端未执行: 需要外部工具(%s);本包不调用解包工具,未写入任何文件",
		joinSortedKeys(tools))
	obs.Facts = append(obs.Facts, newFact(backendStatement,
		evidenceWithLocation(path, map[string]any{
			"path":      path,
			"backend":   "none",
			"needed":    sortedKeys(tools),
			"source":    "backend-probe",
			"degraded":  true,
			"extracted": false,
			"executed":  false,
		}),
		[]string{"binary", "firmware", "degraded", "tier1"}, []string{"artifact:" + path}))
	obs.Summary = statement
	return obs, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinSortedKeys(m map[string]bool) string {
	keys := sortedKeys(m)
	if len(keys) == 0 {
		return "无已知签名,无法确定"
	}
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}
