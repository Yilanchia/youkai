package binary

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ---- ELF fixture ------------------------------------------------------------

type elfSpec struct {
	eType      uint16
	stack      bool
	stackFlags uint32
	relro      bool
	dynamic    bool
}

// buildELF builds a minimal but structurally valid ELF64 file. The fixture is
// synthetic: the point is to exercise the parser, not to run anything.
func buildELF(t *testing.T, spec elfSpec) []byte {
	t.Helper()
	if spec.eType == 0 {
		spec.eType = etExec
	}
	if spec.stackFlags == 0 {
		spec.stackFlags = 0x6 // PF_R|PF_W: non-executable stack
	}
	phnum := 1 // PT_LOAD
	if spec.stack {
		phnum++
	}
	if spec.relro {
		phnum++
	}
	if spec.dynamic {
		phnum++
	}
	const ehsize = 64
	const phentsize = 56
	dynOff := ehsize + phentsize*phnum
	var dynData []byte
	if spec.dynamic {
		dynData = make([]byte, 32)
		binary.LittleEndian.PutUint64(dynData[0:8], dtBindNow)
		binary.LittleEndian.PutUint64(dynData[8:16], 0)
		binary.LittleEndian.PutUint64(dynData[16:24], dtNull)
		binary.LittleEndian.PutUint64(dynData[24:32], 0)
	}
	total := dynOff + len(dynData)

	buf := make([]byte, total)
	copy(buf[:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], spec.eType)
	binary.LittleEndian.PutUint16(buf[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[24:], 0x400000)
	binary.LittleEndian.PutUint64(buf[32:], ehsize) // e_phoff
	binary.LittleEndian.PutUint64(buf[40:], 0)      // e_shoff
	binary.LittleEndian.PutUint32(buf[48:], 0)
	binary.LittleEndian.PutUint16(buf[52:], ehsize)
	binary.LittleEndian.PutUint16(buf[54:], phentsize)
	binary.LittleEndian.PutUint16(buf[56:], uint16(phnum))
	binary.LittleEndian.PutUint16(buf[58:], 64)
	binary.LittleEndian.PutUint16(buf[60:], 0)
	binary.LittleEndian.PutUint16(buf[62:], 0)

	putPhdr := func(index int, ptype, flags uint32, off, vaddr, filesz, memsz uint64) {
		base := ehsize + index*phentsize
		binary.LittleEndian.PutUint32(buf[base:], ptype)
		binary.LittleEndian.PutUint32(buf[base+4:], flags)
		binary.LittleEndian.PutUint64(buf[base+8:], off)
		binary.LittleEndian.PutUint64(buf[base+16:], vaddr)
		binary.LittleEndian.PutUint64(buf[base+24:], 0)
		binary.LittleEndian.PutUint64(buf[base+32:], filesz)
		binary.LittleEndian.PutUint64(buf[base+40:], memsz)
		binary.LittleEndian.PutUint64(buf[base+48:], 0x1000)
	}

	index := 0
	putPhdr(index, ptLoad, 0x5, 0, 0x400000, uint64(total), uint64(total))
	index++
	if spec.stack {
		putPhdr(index, ptGNUStack, spec.stackFlags, 0, 0, 0, 0)
		index++
	}
	if spec.relro {
		putPhdr(index, ptGNURelro, 0x4, 0, 0, 0, 0)
		index++
	}
	if spec.dynamic {
		putPhdr(index, ptDynamic, 0x6, uint64(dynOff), 0x400000+uint64(dynOff), uint64(len(dynData)), uint64(len(dynData)))
		copy(buf[dynOff:], dynData)
	}
	return buf
}

// ---- PE fixture -------------------------------------------------------------

// buildPE builds a minimal PE32+ image with the given DllCharacteristics.
func buildPE(t *testing.T, dllCharacteristics uint16) []byte {
	t.Helper()
	const lfanew = 0x80
	const optionalSize = 0xF0
	buf := make([]byte, lfanew+24+optionalSize)
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], lfanew)
	copy(buf[lfanew:], []byte{'P', 'E', 0, 0})
	coff := lfanew + 4
	binary.LittleEndian.PutUint16(buf[coff:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	binary.LittleEndian.PutUint16(buf[coff+2:], 1)    // NumberOfSections
	binary.LittleEndian.PutUint16(buf[coff+16:], optionalSize)
	binary.LittleEndian.PutUint16(buf[coff+18:], 0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	optional := lfanew + 24
	binary.LittleEndian.PutUint16(buf[optional:], 0x20b) // PE32+
	binary.LittleEndian.PutUint16(buf[optional+70:], dllCharacteristics)
	return buf
}

// ---- APK fixture ------------------------------------------------------------

// buildAPK makes a ZIP with an AndroidManifest.xml, two DEX files, a native
// library, an asset with fake credentials, and optionally a traversal entry.
func buildAPK(t *testing.T, withTraversal bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	add("AndroidManifest.xml", []byte{0x03, 0x00, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef})
	add("classes.dex", append([]byte("dex\n035\x00"), make([]byte, 64)...))
	add("classes2.dex", append([]byte("dex\n035\x00"), make([]byte, 32)...))
	add("lib/arm64-v8a/libnative.so", append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 32)...))
	add("assets/config.json", []byte(`{"api_key":"AKIAIOSFODNN7EXAMPLE","note":"fixture"}`))
	if withTraversal {
		add("../evil.txt", []byte("must not be written outside ArtifactDir"))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// ---- misc fixtures ----------------------------------------------------------

func writeFixture(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

// secretFixture contains one of each class secrets must report, with values
// long enough to be realistic but synthetic.
const secretFixture = `# youkai secrets fixture (synthetic)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_0123456789abcdef0123456789abcdef0123"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK
-----END RSA PRIVATE KEY-----
DB_PASSWORD = "Hunter2-SuperSecret-Passw0rd!"
DATABASE_URL = "postgres://admin:s3cr3tpassvalue@db.internal:5432/app"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
`

var secretFixtureValues = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"ghp_0123456789abcdef0123456789abcdef0123",
	"MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
	"Hunter2-SuperSecret-Passw0rd!",
	"s3cr3tpassvalue",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}
