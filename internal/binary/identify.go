package binary

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"youkai/internal/ledger"
)

// formatInfo is what magic-byte sniffing can honestly say about a file.
type formatInfo struct {
	Format  string         // ELF, PE, Mach-O, APK, ZIP, DEX, WebAssembly, Java class, firmware
	Arch    string         // amd64, x86, arm64, arm, dalvik, jvm, wasm32, unknown
	Details map[string]any // parsed header fields, format specific
	Notes   []string       // explicit "could not determine" notes
}

// elfMachineNames maps e_machine to the architecture label used in facts.
var elfMachineNames = map[uint16]string{
	2:   "sparc",
	3:   "x86",
	8:   "mips",
	20:  "ppc",
	21:  "ppc64",
	40:  "arm",
	62:  "amd64",
	183: "arm64",
	243: "riscv",
}

// sniffFormat opens path and classifies it from its first bytes. It reads no
// more than needed for headers and a bounded ZIP central directory.
func sniffFormat(path string, size int64) (formatInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return formatInfo{}, fmt.Errorf("%w: 打开 %s: %v", ErrRefused, path, err)
	}
	defer f.Close()

	head := make([]byte, 4096)
	n, readErr := io.ReadFull(f, head)
	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return formatInfo{}, fmt.Errorf("%w: 读取 %s 文件头: %v", ErrRefused, path, readErr)
	}
	head = head[:n]
	if len(head) < 4 {
		return formatInfo{Format: "firmware", Arch: "unknown", Details: map[string]any{"size": size},
			Notes: []string{"文件过短,无法识别格式,按原始数据(firmware)处理"}}, nil
	}

	switch {
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		return elfFormat(head)
	case head[0] == 'M' && head[1] == 'Z':
		return peFormat(f, head, size)
	case isZipMagic(head):
		return zipFormat(f, size)
	case bytes.HasPrefix(head, []byte("dex\n")):
		return dexFormat(head), nil
	case bytes.HasPrefix(head, []byte("\x00asm")):
		fi := formatInfo{Format: "WebAssembly", Arch: "wasm32", Details: map[string]any{}}
		if len(head) >= 8 {
			fi.Details["version"] = binary.LittleEndian.Uint32(head[4:8])
		}
		return fi, nil
	case isMachOMagic(head):
		return machoFormat(head), nil
	case binary.BigEndian.Uint32(head[:4]) == 0xcafebabe:
		if looksLikeFatMachO(head, size) {
			return fatMachOFormat(head), nil
		}
		return javaClassFormat(head), nil
	}

	fi := formatInfo{Format: "firmware", Arch: "unknown", Details: map[string]any{}}
	if container := detectFirmwareContainer(head); container != "" {
		fi.Details["container"] = container
		fi.Notes = append(fi.Notes, "按已知固件容器签名识别为 "+container)
	} else {
		fi.Notes = append(fi.Notes, "无匹配的文件格式魔数,按原始固件/未知二进制处理")
	}
	return fi, nil
}

func isZipMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	return (head[0] == 'P' && head[1] == 'K') &&
		((head[2] == 0x03 && head[3] == 0x04) ||
			(head[2] == 0x05 && head[3] == 0x06) ||
			(head[2] == 0x07 && head[3] == 0x08))
}

func isMachOMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(head[:4])
	switch magic {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}

// looksLikeFatMachO validates the 0xCAFEBABE ambiguity. A fat Mach-O stores an
// architecture count (1..20) and a plausible cputype for the first slice right
// after the magic; a Java class stores minor/major versions there (major >= 45).
func looksLikeFatMachO(head []byte, size int64) bool {
	if len(head) < 28 {
		return false
	}
	nfat := binary.BigEndian.Uint32(head[4:8])
	if nfat < 1 || nfat > 20 || size < int64(8+20*nfat) {
		return false
	}
	cpu := binary.BigEndian.Uint32(head[8:12])
	switch cpu {
	case 7, 12, 18, 0x01000007, 0x0100000c, 0x01000012:
		return true
	}
	return false
}

func fatMachOFormat(head []byte) formatInfo {
	fi := formatInfo{Format: "Mach-O", Arch: "fat", Details: map[string]any{"fat": true}}
	if len(head) >= 8 {
		fi.Details["arch_count"] = binary.BigEndian.Uint32(head[4:8])
	}
	if len(head) >= 12 {
		fi.Details["first_cpu"] = fmt.Sprintf("0x%x", binary.BigEndian.Uint32(head[8:12]))
	}
	return fi
}

func javaClassFormat(head []byte) formatInfo {
	fi := formatInfo{Format: "Java class", Arch: "jvm", Details: map[string]any{}}
	if len(head) >= 8 {
		fi.Details["minor_version"] = binary.BigEndian.Uint16(head[4:6])
		fi.Details["major_version"] = binary.BigEndian.Uint16(head[6:8])
	}
	return fi
}

func machoCPUName(cpu uint32) string {
	switch cpu {
	case 7:
		return "x86"
	case 0x01000007:
		return "amd64"
	case 12:
		return "arm"
	case 0x0100000c:
		return "arm64"
	default:
		return "unknown"
	}
}

// machoFormat parses thin Mach-O and fat binaries. cafebabe is ambiguous with
// the Java class magic, so the "fat" count is validated before committing.
func machoFormat(head []byte) formatInfo {
	magic := binary.BigEndian.Uint32(head[:4])
	var order binary.ByteOrder = binary.LittleEndian
	switch magic {
	case 0xfeedface, 0xfeedfacf:
		order = binary.BigEndian
	case 0xcefaedfe, 0xcffaedfe:
		order = binary.LittleEndian
	}
	bits := 32
	if magic == 0xfeedfacf || magic == 0xcffaedfe {
		bits = 64
	}
	fi := formatInfo{Format: "Mach-O", Arch: "unknown", Details: map[string]any{"bits": bits}}
	if len(head) >= 8 {
		cpu := order.Uint32(head[4:8])
		fi.Arch = machoCPUName(cpu)
		fi.Details["cpu_type"] = fmt.Sprintf("0x%x", cpu)
	}
	return fi
}

func elfFormat(head []byte) (formatInfo, error) {
	if len(head) < 20 {
		return formatInfo{}, fmt.Errorf("%w: ELF 文件头被截断", ErrUnavailable)
	}
	class := head[4]
	endian := head[5]
	order := binary.ByteOrder(binary.LittleEndian)
	endianName := "little"
	if endian == 2 {
		order = binary.BigEndian
		endianName = "big"
	}
	className := "ELF32"
	if class == 2 {
		className = "ELF64"
	}
	eType := order.Uint16(head[16:18])
	eMachine := order.Uint16(head[18:20])
	typeName := "unknown"
	switch eType {
	case 1:
		typeName = "REL"
	case 2:
		typeName = "EXEC"
	case 3:
		typeName = "DYN"
	case 4:
		typeName = "CORE"
	}
	arch, ok := elfMachineNames[eMachine]
	if !ok {
		arch = fmt.Sprintf("machine-%d", eMachine)
	}
	fi := formatInfo{
		Format: "ELF",
		Arch:   arch,
		Details: map[string]any{
			"class":       className,
			"endian":      endianName,
			"type":        typeName,
			"machine":     fmt.Sprintf("0x%x", eMachine),
			"machine_num": eMachine,
		},
	}
	return fi, nil
}

func dexFormat(head []byte) formatInfo {
	fi := formatInfo{Format: "DEX", Arch: "dalvik", Details: map[string]any{}}
	if len(head) >= 8 {
		fi.Details["version"] = string(bytes.TrimRight(head[4:8], "\x00"))
	}
	return fi
}

// peFormat parses the DOS/NT headers just far enough to name the format and
// architecture. checksec parses DllCharacteristics separately.
func peFormat(f *os.File, head []byte, size int64) (formatInfo, error) {
	if len(head) < 64 {
		return formatInfo{}, fmt.Errorf("%w: DOS 头被截断", ErrUnavailable)
	}
	lfanew := int64(binary.LittleEndian.Uint32(head[0x3c:0x40]))
	if lfanew <= 0 || lfanew+24 > size {
		return formatInfo{
			Format: "DOS", Arch: "unknown",
			Details: map[string]any{"note": "MZ 但 e_lfanew 越界"},
			Notes:   []string{"有 MZ 头,但 e_lfanew 指向的位置没有有效的 PE 签名"},
		}, nil
	}
	sig := make([]byte, 24)
	if _, err := f.ReadAt(sig, lfanew); err != nil {
		return formatInfo{}, fmt.Errorf("%w: 读取 PE 头: %v", ErrUnavailable, err)
	}
	if !bytes.Equal(sig[:4], []byte{'P', 'E', 0, 0}) {
		return formatInfo{
			Format: "DOS", Arch: "unknown",
			Details: map[string]any{"note": "MZ 后无 PE\\0\\0 签名"},
			Notes:   []string{"有 MZ 头,但缺少 PE 签名;可能是 DOS 可执行文件或损坏文件"},
		}, nil
	}
	machine := binary.LittleEndian.Uint16(sig[4:6])
	sizeOpt := binary.LittleEndian.Uint16(sig[20:22])
	arch := peMachineName(machine)
	fi := formatInfo{
		Format:  "PE",
		Arch:    arch,
		Details: map[string]any{"machine": fmt.Sprintf("0x%x", machine), "size_of_optional_header": sizeOpt},
	}
	return fi, nil
}

func peMachineName(machine uint16) string {
	switch machine {
	case 0x014c:
		return "x86"
	case 0x8664:
		return "amd64"
	case 0x01c0:
		return "arm"
	case 0x01c4:
		return "armnt"
	case 0xaa64:
		return "arm64"
	case 0x0200:
		return "ia64"
	default:
		return "unknown"
	}
}

// zipFormat opens the archive central directory and reports whether the
// AndroidManifest.xml entry exists, which is what makes a ZIP an APK.
func zipFormat(f *os.File, size int64) (formatInfo, error) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		fi := formatInfo{Format: "ZIP", Arch: "unknown", Details: map[string]any{}}
		fi.Notes = append(fi.Notes, "ZIP 目录解析失败:"+clipString(err.Error(), 160))
		return fi, nil
	}
	entries := 0
	hasManifest := false
	hasClassesDex := false
	for i, entry := range zr.File {
		if i >= 20000 {
			break
		}
		entries++
		switch entry.Name {
		case "AndroidManifest.xml":
			hasManifest = true
		}
		if isRootClassesDex(entry.Name) {
			hasClassesDex = true
		}
	}
	fi := formatInfo{
		Format: "ZIP",
		Arch:   "unknown",
		Details: map[string]any{
			"entries":            entries,
			"android_manifest":   hasManifest,
			"root_classes_dex":   hasClassesDex,
			"entries_may_be_cap": entries >= 20000,
		},
	}
	if hasManifest {
		fi.Format = "APK"
		fi.Arch = "dalvik"
	}
	return fi, nil
}

func isRootClassesDex(name string) bool {
	if name == "classes.dex" {
		return true
	}
	// classes2.dex .. classes99.dex
	const prefix = "classes"
	const suffix = ".dex"
	if len(name) <= len(prefix)+len(suffix) || name[:len(prefix)] != prefix || name[len(name)-len(suffix):] != suffix {
		return false
	}
	mid := name[len(prefix) : len(name)-len(suffix)]
	if mid == "" {
		return false
	}
	for i := 0; i < len(mid); i++ {
		if mid[i] < '0' || mid[i] > '9' {
			return false
		}
	}
	return true
}

// identifyCapability is the artifact_identify capability.
func identifyCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	sum, _, err := sha256File(path)
	if err != nil {
		return ledger.Observation{}, err
	}
	fi, err := sniffFormat(path, size)
	if err != nil {
		return ledger.Observation{}, err
	}

	statement := fmt.Sprintf("样本格式:%s arch=%s size=%d", fi.Format, fi.Arch, size)
	evidence := evidenceWithLocation(path, map[string]any{
		"path":        path,
		"source":      "native-magic-parser",
		"format":      fi.Format,
		"arch":        fi.Arch,
		"size":        size,
		"sha256":      sum,
		"executed":    false,
		"network":     false,
		"determinism": "headers parsed locally; no external backend used",
	})
	if len(fi.Details) > 0 {
		evidence["details"] = fi.Details
	}
	if len(fi.Notes) > 0 {
		evidence["notes"] = fi.Notes
	}
	assetProps := map[string]any{
		"format": fi.Format,
		"arch":   fi.Arch,
		"size":   size,
		"sha256": sum,
		"path":   path,
	}
	if len(fi.Details) > 0 {
		assetProps["details"] = fi.Details
	}
	return ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "artifact", "tier1"}, []string{"artifact:" + path})},
		Assets:  []ledger.AssetSeed{{Kind: "artifact", Value: "artifact:" + path, Props: assetProps}},
		Summary: statement,
	}, nil
}
