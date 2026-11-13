package binary

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PE DllCharacteristics bits (winnt.h).
const (
	peHighEntropyVA  = 0x0020
	peDynamicBase    = 0x0040
	peForceIntegrity = 0x0080
	peNXCompat       = 0x0100
	peNoSEH          = 0x0400
	peGuardCF        = 0x4000
)

// peProtections is what the NT headers can prove. SEH and canary need the load
// config / symbol table, so they stay unknown here.
type peProtections struct {
	Machine            string
	Bitness            string
	DllCharacteristics uint16
	ASLR               bool
	HighEntropyVA      bool
	NX                 bool
	CFG                bool
	ForceIntegrity     bool
	SEH                string // always "unknown" in this build
	Canary             string // always "unknown" in this build
	Notes              []string
}

// parsePE reads the DOS header, the NT signature, the COFF header, and the
// optional header far enough to decode DllCharacteristics.
func parsePE(data []byte) (*peProtections, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("%w: DOS 头被截断", ErrUnavailable)
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("%w: 不是 PE 文件(缺少 MZ)", ErrUnavailable)
	}
	lfanew := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if lfanew <= 0 || lfanew+24 > len(data) {
		return nil, fmt.Errorf("%w: PE e_lfanew 越界(%d)", ErrUnavailable, lfanew)
	}
	if !bytes.Equal(data[lfanew:lfanew+4], []byte{'P', 'E', 0, 0}) {
		return nil, fmt.Errorf("%w: MZ 之后缺少 PE\\0\\0 签名", ErrUnavailable)
	}
	machine := binary.LittleEndian.Uint16(data[lfanew+4 : lfanew+6])
	sizeOptional := int(binary.LittleEndian.Uint16(data[lfanew+20 : lfanew+22]))
	optional := lfanew + 24
	if sizeOptional < 72 || optional+72 > len(data) {
		return nil, fmt.Errorf("%w: PE 可选头过小或越界(SizeOfOptionalHeader=%d)", ErrUnavailable, sizeOptional)
	}
	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	bitness := "unknown"
	switch magic {
	case 0x10b:
		bitness = "PE32"
	case 0x20b:
		bitness = "PE32+"
	default:
		// DllCharacteristics still sits at the same offset in both layouts;
		// report the unknown magic rather than refusing the whole file.
		bitness = fmt.Sprintf("unknown-magic-0x%x", magic)
	}
	// DllCharacteristics is at optional-header offset 70 for PE32 and PE32+.
	dll := binary.LittleEndian.Uint16(data[optional+70 : optional+72])

	prot := &peProtections{
		Machine:            peMachineName(machine),
		Bitness:            bitness,
		DllCharacteristics: dll,
		ASLR:               dll&peDynamicBase != 0,
		HighEntropyVA:      dll&peHighEntropyVA != 0,
		NX:                 dll&peNXCompat != 0,
		CFG:                dll&peGuardCF != 0,
		ForceIntegrity:     dll&peForceIntegrity != 0,
		SEH:                "unknown",
		Canary:             "unknown",
		Notes: []string{
			"SEH/SAFESEH 与 /GS canary 需要 load config 或符号表,本构建未解析,如实报 unknown",
		},
	}
	if bitness != "PE32" && bitness != "PE32+" {
		prot.Notes = append(prot.Notes, "可选头 magic 未知,但 DllCharacteristics 仍按固定偏移读取")
	}
	return prot, nil
}
