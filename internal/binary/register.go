package binary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"youkai/internal/ledger"
)

// registerCapability is artifact_register. It hashes the sample and, unless
// copy=false, places a 0600 copy inside ArtifactDir. It never executes and
// never touches the network. Symlinks and files over 64 MiB are refused.
func registerCapability(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	path, size, err := inputFilePath(argString(args, "path"), false)
	if err != nil {
		return ledger.Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return ledger.Observation{}, err
	}
	sum, hashedSize, err := sha256File(path)
	if err != nil {
		return ledger.Observation{}, err
	}
	if hashedSize != size {
		return ledger.Observation{}, fmt.Errorf("%w: 计算 sha256 时文件大小发生变化(%d → %d): %s", ErrRefused, size, hashedSize, path)
	}

	doCopy := argBool(args, "copy", true)
	isolatedPath := ""
	copiedSHA := ""
	if doCopy {
		dir, err := artifactDir(env)
		if err != nil {
			return ledger.Observation{}, err
		}
		name := fmt.Sprintf("%s-%s", sum[:16], filepath.Base(path))
		dest, err := ensureWithin(dir, filepath.Join(dir, name))
		if err != nil {
			return ledger.Observation{}, err
		}
		copiedSHA, err = copyFileBounded(path, dest)
		if err != nil {
			return ledger.Observation{}, err
		}
		if copiedSHA != sum {
			_ = os.Remove(dest)
			return ledger.Observation{}, fmt.Errorf("%w: 复制后的 sha256 与被分析文件不一致(拒绝登记): %s", ErrRefused, dest)
		}
		isolatedPath = dest
	}

	statement := fmt.Sprintf("样本已登记: sha256=%s size=%d 隔离副本=%s (未执行、未联网)",
		sum, size, orNone(isolatedPath))
	evidence := evidenceWithLocation(path, map[string]any{
		"path":          path,
		"sha256":        sum,
		"size":          size,
		"copied":        doCopy,
		"isolated_path": isolatedPath,
		"mode":          "0600",
		"executed":      false,
		"network":       false,
	})
	assetProps := map[string]any{
		"format":        "unknown-until-identify",
		"size":          size,
		"sha256":        sum,
		"path":          path,
		"isolated_path": isolatedPath,
	}
	return ledger.Observation{
		Facts: []ledger.FactSeed{newFact(statement, evidence,
			[]string{"binary", "artifact", "registered", "tier1"}, []string{"artifact:" + path})},
		Assets:  []ledger.AssetSeed{{Kind: "artifact", Value: "artifact:" + path, Props: assetProps}},
		Summary: statement,
	}, nil
}

// copyFileBounded copies src to dst with mode 0600 while hashing the bytes it
// writes, so the returned digest describes exactly what landed on disk.
func copyFileBounded(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("%w: 打开源文件 %s: %v", ErrRefused, src, err)
	}
	defer in.Close()

	// Refuse to overwrite a pre-existing artifact copy: it may belong to a
	// different sample whose name collided.
	if _, err := os.Lstat(dst); err == nil {
		return "", fmt.Errorf("%w: 目标副本已存在,拒绝覆盖: %s", ErrRefused, dst)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w: 创建隔离副本 %s: %v", ErrRefused, dst, err)
	}
	hasher := sha256.New()
	// LimitReader guards against a file that grew after the size check.
	_, copyErr := io.Copy(io.MultiWriter(out, hasher), io.LimitReader(in, maxFileSize+1))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("%w: 复制到隔离目录失败: %v", ErrRefused, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("%w: 关闭隔离副本失败: %v", ErrRefused, closeErr)
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("%w: 设置隔离副本权限 0600 失败: %v", ErrRefused, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func orNone(s string) string {
	if s == "" {
		return "未复制"
	}
	return s
}
