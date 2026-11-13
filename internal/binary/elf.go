package binary

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
)

// ELF constants used by the protector checks (from the ELF gABI and LSB).
const (
	etRel  = 1
	etExec = 2
	etDyn  = 3
	etCore = 4

	ptLoad       = 1
	ptDynamic    = 2
	ptGNUStack   = 0x6474e551
	ptGNURelro   = 0x6474e552
	pfExecutable = 0x1

	shtSymtab = 2
	shtDynsym = 11

	dtNull    = 0
	dtBindNow = 24
	dtFlags   = 30
	dtFlags1  = 0x6ffffffb

	dfBindNow = 0x8
	df1Now    = 0x1
)

var fortifySymbolRe = regexp.MustCompile(`__[a-z0-9_]+_chk\x00`)

// elfProtections is the slice of ELF structure checksec reports. Every field is
// derived from parsed bytes; anything not parseable stays "unknown".
type elfProtections struct {
	Class   string
	Endian  string
	Type    string
	Machine string
	NX      bool
	PIE     bool
	RELRO   string
	Canary  string
	Fortify string
	Dynamic bool
	Notes   []string
}

// parseELF parses the ELF header, program headers, dynamic segment, and the
// symbol string tables. It never executes or maps the file.
func parseELF(data []byte) (*elfProtections, error) {
	if len(data) < 52 {
		return nil, fmt.Errorf("%w: ELF 文件长度不足(可能被截断)", ErrUnavailable)
	}
	if !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, fmt.Errorf("%w: 不是 ELF 文件", ErrUnavailable)
	}
	class := data[4]
	dataEncoding := data[5]
	var order binary.ByteOrder = binary.LittleEndian
	endianName := "little"
	switch dataEncoding {
	case 1:
	case 2:
		order = binary.BigEndian
		endianName = "big"
	default:
		return nil, fmt.Errorf("%w: 未知 ELF 数据编码 %d", ErrUnavailable, dataEncoding)
	}
	is64 := false
	className := "ELF32"
	switch class {
	case 1:
	case 2:
		is64 = true
		className = "ELF64"
	default:
		return nil, fmt.Errorf("%w: 未知 ELF class %d", ErrUnavailable, class)
	}

	u16 := func(off int, what string) (uint16, error) {
		if off < 0 || off+2 > len(data) {
			return 0, fmt.Errorf("%w: ELF %s 越界(偏移 %d)", ErrUnavailable, what, off)
		}
		return order.Uint16(data[off : off+2]), nil
	}
	u32 := func(off int, what string) (uint32, error) {
		if off < 0 || off+4 > len(data) {
			return 0, fmt.Errorf("%w: ELF %s 越界(偏移 %d)", ErrUnavailable, what, off)
		}
		return order.Uint32(data[off : off+4]), nil
	}
	u64 := func(off int, what string) (uint64, error) {
		if off < 0 || off+8 > len(data) {
			return 0, fmt.Errorf("%w: ELF %s 越界(偏移 %d)", ErrUnavailable, what, off)
		}
		return order.Uint64(data[off : off+8]), nil
	}

	eTypeU, err := u16(16, "e_type")
	if err != nil {
		return nil, err
	}
	eMachine, err := u16(18, "e_machine")
	if err != nil {
		return nil, err
	}

	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum uint16
	if is64 {
		if phoff, err = u64(32, "e_phoff"); err != nil {
			return nil, err
		}
		if shoff, err = u64(40, "e_shoff"); err != nil {
			return nil, err
		}
		if phentsize, err = u16(54, "e_phentsize"); err != nil {
			return nil, err
		}
		if phnum, err = u16(56, "e_phnum"); err != nil {
			return nil, err
		}
		if shentsize, err = u16(58, "e_shentsize"); err != nil {
			return nil, err
		}
		if shnum, err = u16(60, "e_shnum"); err != nil {
			return nil, err
		}
	} else {
		phoffRaw, err := u32(28, "e_phoff")
		if err != nil {
			return nil, err
		}
		shoffRaw, err := u32(32, "e_shoff")
		if err != nil {
			return nil, err
		}
		phoff, shoff = uint64(phoffRaw), uint64(shoffRaw)
		if phentsize, err = u16(42, "e_phentsize"); err != nil {
			return nil, err
		}
		if phnum, err = u16(44, "e_phnum"); err != nil {
			return nil, err
		}
		if shentsize, err = u16(46, "e_shentsize"); err != nil {
			return nil, err
		}
		if shnum, err = u16(48, "e_shnum"); err != nil {
			return nil, err
		}
	}

	prot := &elfProtections{
		Class:   className,
		Endian:  endianName,
		Type:    elfTypeName(eTypeU),
		Machine: elfMachineName(eMachine),
		Canary:  "unknown",
		Fortify: "unknown",
	}
	prot.PIE = eTypeU == etDyn
	if prot.PIE {
		prot.Notes = append(prot.Notes, "e_type=ET_DYN:可能是 PIE 可执行文件,也可能是共享库,需结合入口点/用途判断")
	}

	// ---- program headers: NX and RELRO -----------------------------------
	hasStack := false
	stackExecutable := false
	hasRelro := false
	var dynamicOff, dynamicSize uint64
	if phnum == 0 {
		prot.Notes = append(prot.Notes, "无程序头:按内核默认(栈不可执行)推断 NX,并无法判定 RELRO")
	} else {
		expected := uint16(32)
		if is64 {
			expected = 56
		}
		if phnum > 1024 {
			return nil, fmt.Errorf("%w: 程序头数量异常(%d)", ErrUnavailable, phnum)
		}
		if phentsize < expected || phoff == 0 || phoff+uint64(phentsize)*uint64(phnum) > uint64(len(data)) {
			return nil, fmt.Errorf("%w: 程序头表越界或结构异常(phoff=%d, num=%d, entsize=%d)", ErrUnavailable, phoff, phnum, phentsize)
		}
		for i := 0; i < int(phnum); i++ {
			base := int(phoff) + i*int(phentsize)
			pType := uint32(0)
			var pFlags uint32
			var pOffset, pFilesz uint64
			if is64 {
				pType, err = u32(base, "p_type")
				if err != nil {
					return nil, err
				}
				pFlags, err = u32(base+4, "p_flags")
				if err != nil {
					return nil, err
				}
				if pOffset, err = u64(base+8, "p_offset"); err != nil {
					return nil, err
				}
				if pFilesz, err = u64(base+32, "p_filesz"); err != nil {
					return nil, err
				}
			} else {
				pType, err = u32(base, "p_type")
				if err != nil {
					return nil, err
				}
				off32, err := u32(base+4, "p_offset")
				if err != nil {
					return nil, err
				}
				pOffset = uint64(off32)
				filesz32, err := u32(base+16, "p_filesz")
				if err != nil {
					return nil, err
				}
				pFilesz = uint64(filesz32)
				pFlags, err = u32(base+24, "p_flags")
				if err != nil {
					return nil, err
				}
			}
			switch pType {
			case ptLoad:
				// Only relevant for completeness; nothing to report yet.
			case ptGNUStack:
				hasStack = true
				stackExecutable = pFlags&pfExecutable != 0
			case ptGNURelro:
				hasRelro = true
			case ptDynamic:
				prot.Dynamic = true
				dynamicOff, dynamicSize = pOffset, pFilesz
			}
		}
	}
	// A missing PT_GNU_STACK means the loader uses its non-executable default,
	// so NX is present; that is the honest reading, not a guess about intent.
	prot.NX = !hasStack || !stackExecutable
	if !hasStack {
		prot.Notes = append(prot.Notes, "无 PT_GNU_STACK:按加载器默认(非可执行栈)判定 NX=yes")
	}

	bindNow := false
	if hasRelro {
		if prot.Dynamic && dynamicOff > 0 && dynamicSize > 0 {
			var dynErr error
			bindNow, dynErr = elfBindNow(data, is64, order, dynamicOff, dynamicSize)
			if dynErr != nil {
				prot.Notes = append(prot.Notes, "动态段解析失败(RELRO 只能报 partial):"+dynErr.Error())
			}
		}
		if bindNow {
			prot.RELRO = "full"
		} else {
			prot.RELRO = "partial"
			if !prot.Dynamic {
				prot.Notes = append(prot.Notes, "有 PT_GNU_RELRO 但无动态段:无法看到 BIND_NOW,如实报 partial")
			}
		}
	} else {
		prot.RELRO = "none"
	}
	// RELRO/PIE are only meaningful for executables and shared objects. For a
	// relocatable object or a core file, saying "none" would invent a finding.
	if prot.Type != "EXEC" && prot.Type != "DYN" {
		prot.RELRO = "n/a"
		prot.Notes = append(prot.Notes, fmt.Sprintf("e_type=%s 不是可执行/共享对象,RELRO 与 PIE 不适用", prot.Type))
	}

	// ---- section headers: canary + FORTIFY -------------------------------
	elfSymbolState(prot, data, is64, order, shoff, shentsize, shnum, u32, u64)
	return prot, nil
}

func elfTypeName(t uint16) string {
	switch t {
	case 0:
		return "NONE"
	case etRel:
		return "REL"
	case etExec:
		return "EXEC"
	case etDyn:
		return "DYN"
	case etCore:
		return "CORE"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func elfMachineName(m uint16) string {
	if name, ok := elfMachineNames[m]; ok {
		return fmt.Sprintf("%s(0x%x)", name, m)
	}
	return fmt.Sprintf("machine-0x%x", m)
}

// elfBindNow reads the dynamic segment and looks for DT_BIND_NOW, DF_BIND_NOW,
// or DF_1_NOW. DT_NULL terminates the array per the spec.
func elfBindNow(data []byte, is64 bool, order binary.ByteOrder, off, size uint64) (bool, error) {
	entrySize := uint64(8)
	if is64 {
		entrySize = 16
	}
	if off+size > uint64(len(data)) {
		return false, fmt.Errorf("动态段越界(off=%d size=%d)", off, size)
	}
	count := size / entrySize
	if count > 8192 {
		count = 8192
	}
	for i := uint64(0); i < count; i++ {
		base := off + i*entrySize
		var tag uint64
		var val uint64
		if is64 {
			tag = order.Uint64(data[base : base+8])
			val = order.Uint64(data[base+8 : base+16])
		} else {
			tag = uint64(order.Uint32(data[base : base+4]))
			val = uint64(order.Uint32(data[base+4 : base+8]))
		}
		switch tag {
		case dtNull:
			return false, nil
		case dtBindNow:
			return true, nil
		case dtFlags:
			if val&dfBindNow != 0 {
				return true, nil
			}
		case dtFlags1:
			if val&df1Now != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// elfSymbolState fills Canary and Fortify from the symbol string tables. The
// absence of a symbol table is reported as unknown, never as "no".
func elfSymbolState(
	prot *elfProtections,
	data []byte,
	is64 bool,
	order binary.ByteOrder,
	shoff uint64,
	shentsize, shnum uint16,
	u32 func(int, string) (uint32, error),
	u64 func(int, string) (uint64, error),
) {
	minEnt := uint16(40)
	if is64 {
		minEnt = 64
	}
	if shoff == 0 || shnum == 0 {
		prot.Notes = append(prot.Notes, "无节头表:canary 与 FORTIFY 无法判定(unknown,不猜测)")
		return
	}
	if shnum > 4096 || shentsize < minEnt || shoff+uint64(shentsize)*uint64(shnum) > uint64(len(data)) {
		prot.Notes = append(prot.Notes, "节头表越界或异常:canary 与 FORTIFY 无法判定(unknown)")
		return
	}

	var tables [][]byte
	sawSymbolTable := false
	for i := 0; i < int(shnum); i++ {
		base := int(shoff) + i*int(shentsize)
		shType, err := u32(base+4, "sh_type")
		if err != nil {
			prot.Notes = append(prot.Notes, "节头读取失败:"+err.Error())
			return
		}
		if shType != shtSymtab && shType != shtDynsym {
			continue
		}
		sawSymbolTable = true
		var linkIndex uint32
		if is64 {
			linkIndex, err = u32(base+40, "sh_link")
			if err != nil {
				prot.Notes = append(prot.Notes, "符号表 sh_link 读取失败:"+err.Error())
				return
			}
		} else {
			linkIndex, err = u32(base+24, "sh_link")
			if err != nil {
				prot.Notes = append(prot.Notes, "符号表 sh_link 读取失败:"+err.Error())
				return
			}
		}
		if linkIndex == 0 || linkIndex >= uint32(shnum) {
			continue
		}
		linkBase := int(shoff) + int(linkIndex)*int(shentsize)
		var strOff, strSize uint64
		if is64 {
			if strOff, err = u64(linkBase+24, "sh_offset"); err != nil {
				prot.Notes = append(prot.Notes, "字符串表偏移读取失败:"+err.Error())
				return
			}
			if strSize, err = u64(linkBase+32, "sh_size"); err != nil {
				prot.Notes = append(prot.Notes, "字符串表大小读取失败:"+err.Error())
				return
			}
		} else {
			off32, err := u32(linkBase+16, "sh_offset")
			if err != nil {
				prot.Notes = append(prot.Notes, "字符串表偏移读取失败:"+err.Error())
				return
			}
			size32, err := u32(linkBase+20, "sh_size")
			if err != nil {
				prot.Notes = append(prot.Notes, "字符串表大小读取失败:"+err.Error())
				return
			}
			strOff, strSize = uint64(off32), uint64(size32)
		}
		const maxStrtab = 8 << 20
		if strSize > maxStrtab {
			strSize = maxStrtab
		}
		if strOff+strSize > uint64(len(data)) {
			prot.Notes = append(prot.Notes, "字符串表越界,跳过该表")
			continue
		}
		tables = append(tables, data[strOff:strOff+strSize])
	}

	if !sawSymbolTable {
		prot.Notes = append(prot.Notes, "未找到 .symtab/.dynsym,canary 与 FORTIFY 无法判定(unknown)")
		return
	}
	if len(tables) == 0 {
		prot.Notes = append(prot.Notes, "符号表存在但字符串表不可读,canary 与 FORTIFY 无法判定(unknown)")
		return
	}
	canary := false
	fortify := false
	for _, table := range tables {
		if bytes.Contains(table, []byte("__stack_chk_fail")) || bytes.Contains(table, []byte("__stack_chk_guard")) {
			canary = true
		}
		if fortifySymbolRe.Match(table) {
			fortify = true
		}
	}
	prot.Canary = boolToYesNo(canary)
	prot.Fortify = boolToYesNo(fortify)
	if !canary {
		prot.Notes = append(prot.Notes, "符号表中无 __stack_chk_fail/__stack_chk_guard:canary=no(基于已解析符号表)")
	}
}

func boolToYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
