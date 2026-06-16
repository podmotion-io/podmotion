/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package provenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
)

// FilesFromTarGz reads a gzip-compressed tar and returns the per-file (name,size,sha256) entries
// for every regular file, using filepath.Base(name) as the flat name (mirrors the extract logic
// in PutCheckpointTar). limit bounds total decompressed bytes (gzip-bomb guard, ADR-SEC-A §2.3).
func FilesFromTarGz(tarData []byte, limit int64) ([]FileEntry, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(tarData))
	if err != nil {
		return nil, fmt.Errorf("ADR-SEC-B: gzip open: %w", err)
	}
	defer gzr.Close()
	lr := io.LimitReader(gzr, limit+1)
	tr := tar.NewReader(lr)
	var entries []FileEntry
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ADR-SEC-B: tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." || name == ".." {
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, tr)
		if err != nil {
			return nil, fmt.Errorf("ADR-SEC-B: hash %s: %w", name, err)
		}
		total += n
		if total > limit {
			return nil, fmt.Errorf("ADR-SEC-B: decompressed size exceeds %d bytes (gzip-bomb guard)", limit)
		}
		entries = append(entries, FileEntry{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return entries, nil
}

// FindFile returns the entry with the given name, or nil.
func FindFile(files []FileEntry, name string) *FileEntry {
	for i := range files {
		if files[i].Name == name {
			return &files[i]
		}
	}
	return nil
}
