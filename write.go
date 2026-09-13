package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/phishingclub/ipdata/format"
)

// tarFile is one file to place in a package archive
type tarFile struct {
	name string
	data []byte
}

// writePackage writes <out>/<name>.tar.gz and returns its manifest entry.
// Timestamps inside the archive are fixed so the same data gives the same bytes.
func writePackage(out string, info format.Info, b *built) (format.ManifestPackage, error) {
	infoBytes, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return format.ManifestPackage{}, err
	}
	files := []tarFile{
		{format.FilePackage, infoBytes},
		{format.FileIPv4, b.ipv4},
		{format.FileIPv6, b.ipv6},
		{format.FileValues, b.values},
	}

	fileName := info.Name + ".tar.gz"
	path := filepath.Join(out, fileName)
	f, err := os.Create(path)
	if err != nil {
		return format.ManifestPackage{}, err
	}
	hash := sha256.New()
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return format.ManifestPackage{}, err
	}
	tw := tar.NewWriter(gz)
	for _, tf := range files {
		hdr := &tar.Header{
			Name:    tf.name,
			Mode:    0o644,
			Size:    int64(len(tf.data)),
			ModTime: time.Unix(0, 0),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			f.Close()
			return format.ManifestPackage{}, err
		}
		if _, err := tw.Write(tf.data); err != nil {
			f.Close()
			return format.ManifestPackage{}, err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return format.ManifestPackage{}, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return format.ManifestPackage{}, err
	}
	if err := f.Close(); err != nil {
		return format.ManifestPackage{}, err
	}

	// hash the finished file as written to disk
	data, err := os.ReadFile(path)
	if err != nil {
		return format.ManifestPackage{}, err
	}
	hash.Write(data)
	return format.ManifestPackage{
		File:        fileName,
		Size:        int64(len(data)),
		SHA256:      hex.EncodeToString(hash.Sum(nil)),
		ContentHash: info.ContentHash,
		IPv4Records: info.IPv4Records,
		IPv6Records: info.IPv6Records,
		Values:      info.Values,
	}, nil
}

// writeJSON writes v as indented JSON
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
