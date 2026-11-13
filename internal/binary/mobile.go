package binary

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"youkai/internal/ledger"
)

const (
	maxMobileEntries     = 20000
	maxExtractEntrySize  = 32 << 20
	maxExtractTotal      = 256 << 20
	maxMobileSecretFiles = 2000
	maxMobileSecretBytes = 32 << 20
)

// mobileUnpackCapability inventories an APK as a ZIP container. With
// extract=true it writes entries only inside ArtifactDir, refusing path
// traversal, then re-scans the extracted tree for secrets.
func mobileUnpackCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), true)
	if err != nil {
		return ledger.Observation{}, err
	}
	if size < 4 {
		return ledger.Observation{}, fmt.Errorf("%w: 文件过短,不是 APK/ZIP", ErrUnavailable)
	}
	fi, err := sniffFormat(path, size)
	if err != nil {
		return ledger.Observation{}, err
	}
	if fi.Format != "APK" && fi.Format != "ZIP" {
		return ledger.Observation{}, fmt.Errorf("%w: mobile_unpack 只接受 ZIP/APK,该文件是 %s", ErrUnavailable, fi.Format)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("%w: 打开 ZIP/APK: %v", ErrUnavailable, err)
	}
	defer zr.Close()

	sum, _, err := sha256File(path)
	if err != nil {
		return ledger.Observation{}, err
	}

	var (
		entries    int
		manifest   bool
		dexFiles   []*zip.File
		libFiles   []*zip.File
		assetBytes int64
		truncated  bool
	)
	for i, entry := range zr.File {
		if i >= maxMobileEntries {
			truncated = true
			break
		}
		entries++
		name := entry.Name
		switch {
		case name == "AndroidManifest.xml":
			manifest = true
		case isRootClassesDex(name):
			dexFiles = append(dexFiles, entry)
		case strings.HasPrefix(name, "lib/") && strings.HasSuffix(strings.ToLower(name), ".so"):
			libFiles = append(libFiles, entry)
		case strings.HasPrefix(name, "assets/") && !entry.FileInfo().IsDir():
			assetBytes += int64(entry.UncompressedSize64)
		}
	}

	obs := ledger.Observation{}
	inventoryStatement := fmt.Sprintf(
		"mobile_unpack: %s AndroidManifest.xml=%t 条目=%d dex=%d 原生库=%d assets=%d 字节",
		path, manifest, entries, len(dexFiles), len(libFiles), assetBytes)
	inventoryEvidence := evidenceWithLocation(path, map[string]any{
		"path":              path,
		"container":         fi.Format,
		"sha256":            sum,
		"entries":           entries,
		"entries_truncated": truncated,
		"android_manifest":  manifest,
		"dex_count":         len(dexFiles),
		"native_lib_count":  len(libFiles),
		"asset_bytes":       assetBytes,
		"source":            "native-zip-reader",
		"executed":          false,
	})
	obs.Facts = append(obs.Facts, newFact(inventoryStatement, inventoryEvidence,
		[]string{"binary", "mobile", "apk", "tier1"}, []string{"artifact:" + path}))

	for _, entry := range dexFiles {
		obs.Assets = append(obs.Assets, ledger.AssetSeed{
			Kind:  "artifact",
			Value: "artifact:" + path + "!" + entry.Name,
			Props: map[string]any{
				"container": path,
				"entry":     entry.Name,
				"type":      "dex",
				"size":      entry.UncompressedSize64,
			},
		})
	}
	for _, entry := range libFiles {
		obs.Assets = append(obs.Assets, ledger.AssetSeed{
			Kind:  "artifact",
			Value: "artifact:" + path + "!" + entry.Name,
			Props: map[string]any{
				"container": path,
				"entry":     entry.Name,
				"type":      "native-lib",
				"size":      entry.UncompressedSize64,
			},
		})
	}

	extract := argBool(args, "extract", false)
	if extract {
		dir, err := artifactDir(env)
		if err != nil {
			return ledger.Observation{}, err
		}
		outDir, err := ensureWithin(dir, filepath.Join(dir, "mobile-"+sum[:16]))
		if err != nil {
			return ledger.Observation{}, err
		}
		extracted, skipped, extractErr := extractAPKEntries(ctx, env, zr.File, outDir)
		if extractErr != nil {
			return ledger.Observation{}, extractErr
		}
		statement := fmt.Sprintf("mobile_unpack: 已解包 %d 项到 %s(仅 ArtifactDir 内,已防路径穿越;跳过 %d 项)",
			extracted, outDir, len(skipped))
		ev := evidenceWithLocation(outDir, map[string]any{
			"path":         path,
			"output_dir":   outDir,
			"extracted":    extracted,
			"skipped":      clipStrings(skipped, 30),
			"source":       "native-zip-reader",
			"executed":     false,
			"safe_extract": true,
		})
		obs.Facts = append(obs.Facts, newFact(statement, ev,
			[]string{"binary", "mobile", "extracted", "tier1"}, []string{"artifact:" + path}))

		hits, scanErr := scanExtractedSecrets(ctx, outDir)
		if scanErr != nil {
			return ledger.Observation{}, scanErr
		}
		if len(hits) > 0 {
			obs.Findings = append(obs.Findings, secretFindings(hits, path)...)
			byClass := map[string]int{}
			for _, hit := range hits {
				byClass[hit.Class]++
			}
			secretStatement := fmt.Sprintf("mobile_unpack: 解包后扫描凭据命中 %d 处(仅脱敏预览,未验证有效性)", len(hits))
			obs.Facts = append(obs.Facts, newFact(secretStatement,
				evidenceWithLocation(outDir, map[string]any{
					"path":       path,
					"output_dir": outDir,
					"hits":       len(hits),
					"by_class":   byClass,
					"redacted":   true,
					"validated":  false,
					"source":     "native-regex-sweep",
				}),
				[]string{"binary", "secrets", "mobile", "tier1"}, []string{"artifact:" + path}))
		}
	}

	obs.Summary = inventoryStatement
	return obs, nil
}

// zipEntryRel normalises a ZIP entry name and rejects traversal, absolute
// names, and Windows volume/ADS syntax.
func zipEntryRel(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("条目名含 NUL 字节")
	}
	slash := strings.ReplaceAll(name, "\\", "/")
	cleaned := path.Clean(slash)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("条目路径越界(疑似路径穿越):%s", name)
	}
	if strings.Contains(cleaned, ":") {
		return "", fmt.Errorf("条目名含 Windows 卷/ADS 语法:%s", name)
	}
	rel := filepath.FromSlash(cleaned)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("条目是绝对路径:%s", name)
	}
	return rel, nil
}

// extractAPKEntries writes selected entries under outDir. Every destination is
// containment-checked, entries are size-capped, and symlinks are skipped.
func extractAPKEntries(ctx context.Context, env *Env, entries []*zip.File, outDir string) (int, []string, error) {
	dir, err := artifactDir(env)
	if err != nil {
		return 0, nil, err
	}
	if _, err := ensureWithin(dir, outDir); err != nil {
		return 0, nil, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return 0, nil, fmt.Errorf("%w: 创建解包目录 %s: %v", ErrRefused, outDir, err)
	}

	extracted := 0
	var skipped []string
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return extracted, skipped, err
		}
		if extracted >= maxMobileEntries {
			skipped = append(skipped, "(条目数达到上限)")
			break
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, entry.Name+" (符号链接,跳过)")
			continue
		}
		rel, err := zipEntryRel(entry.Name)
		if err != nil {
			skipped = append(skipped, entry.Name+" ("+err.Error()+")")
			continue
		}
		if int64(entry.UncompressedSize64) > maxExtractEntrySize || total+int64(entry.UncompressedSize64) > maxExtractTotal {
			skipped = append(skipped, entry.Name+" (超过解包大小上限)")
			continue
		}
		dest, err := ensureWithin(outDir, filepath.Join(outDir, rel))
		if err != nil {
			skipped = append(skipped, entry.Name+" ("+err.Error()+")")
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return extracted, skipped, fmt.Errorf("%w: 创建目录 %s: %v", ErrRefused, filepath.Dir(dest), err)
		}
		written, err := extractOneEntry(entry, dest)
		if err != nil {
			skipped = append(skipped, entry.Name+" ("+clipString(err.Error(), 120)+")")
			continue
		}
		// Account for the bytes actually written, not the size the archive
		// claimed, so a lying central directory cannot bypass the total cap.
		total += written
		if total > maxExtractTotal {
			_ = os.Remove(dest)
			skipped = append(skipped, entry.Name+" (实际解包超过总量上限,已删除)")
			break
		}
		extracted++
	}
	return extracted, skipped, nil
}

func extractOneEntry(entry *zip.File, dest string) (int64, error) {
	if _, err := os.Lstat(dest); err == nil {
		return 0, fmt.Errorf("目标已存在,拒绝覆盖")
	}
	rc, err := entry.Open()
	if err != nil {
		return 0, fmt.Errorf("打开条目: %v", err)
	}
	defer rc.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("创建文件: %v", err)
	}
	// LimitReader stops a lying central directory from writing more than the cap.
	written, copyErr := io.Copy(out, io.LimitReader(rc, maxExtractEntrySize+1))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dest)
		return 0, fmt.Errorf("写入: %v", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(dest)
		return 0, fmt.Errorf("关闭: %v", closeErr)
	}
	if written > maxExtractEntrySize {
		_ = os.Remove(dest)
		return 0, fmt.Errorf("条目实际大小超过单文件上限")
	}
	return written, nil
}

// scanExtractedSecrets re-scans the unpacked tree. Only text-like files are
// read; DEX/native libraries are reported as a coverage limitation instead of
// having binary regexes run over them.
func scanExtractedSecrets(ctx context.Context, root string) ([]secretHit, error) {
	hits := []secretHit{}
	seen := map[string]bool{}
	files := 0
	var total int64
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if files >= maxMobileSecretFiles || len(hits) >= maxSecretHits {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || total+info.Size() > maxMobileSecretBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if looksBinary(data) && !isTextExtension(strings.ToLower(filepath.Ext(p))) {
			return nil
		}
		files++
		total += int64(len(data))
		return scanSecretsBytes(ctx, p, data, seen, &hits)
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return hits, nil
}
