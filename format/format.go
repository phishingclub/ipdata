// Package format describes the package files produced by ipdata and read by
// Phishing Club. It has no dependencies outside the standard library so it can
// be copied as is into the consumer.
//
// A package is a tar.gz holding two JSON files:
//
//	package.json  metadata, see Info
//	entries.json  one entry per country or autonomous system with its prefixes
//
// entries.json is a JSON array with one entry per line so it can be read with
// any JSON tool or grepped directly. Entries are sorted by country code or by
// ASN, and the prefixes inside an entry are sorted by address. The same prefix
// can appear in more than one ASN entry when several systems announce it, so
// a lookup should collect every entry matching the longest prefix.
package format

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Version is the format version written to package.json and manifest.json.
	Version = 1

	FilePackage = "package.json"
	FileEntries = "entries.json"

	PackageGeoIP = "geoip"
	PackageASN   = "asn"
)

// Info is the content of package.json.
type Info struct {
	Format       int    `json:"format"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Created      string `json:"created"`
	Source       string `json:"source"`
	License      string `json:"license"`
	Entries      int    `json:"entries"`
	IPv4Prefixes int    `json:"ipv4_prefixes"`
	IPv6Prefixes int    `json:"ipv6_prefixes"`
	ContentHash  string `json:"content_hash"`
}

// Manifest is the content of manifest.json published next to the packages.
// A consumer fetches this one file to learn what the latest release holds.
type Manifest struct {
	Format   int                        `json:"format"`
	Version  string                     `json:"version"`
	Created  string                     `json:"created"`
	Packages map[string]ManifestPackage `json:"packages"`
}

// ManifestPackage describes one package file in a release.
type ManifestPackage struct {
	File         string `json:"file"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	ContentHash  string `json:"content_hash"`
	Entries      int    `json:"entries"`
	IPv4Prefixes int    `json:"ipv4_prefixes"`
	IPv6Prefixes int    `json:"ipv6_prefixes"`
}

// GeoIPEntry is one country in the geoip package.
type GeoIPEntry struct {
	Code string   `json:"code"`
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// ASNEntry is one autonomous system in the asn package.
type ASNEntry struct {
	ASN     uint32   `json:"asn"`
	Handle  string   `json:"handle"`
	Name    string   `json:"name"`
	Country string   `json:"country"`
	IPv4    []string `json:"ipv4"`
	IPv6    []string `json:"ipv6"`
}

// Package is a package loaded from disk. Entries holds the raw entries.json,
// decode it with GeoIP or ASN depending on Info.Name.
type Package struct {
	Info    Info
	Entries json.RawMessage
}

// ContentHash hashes entries.json, so it stays the same across builds when
// the upstream data did not change.
func ContentHash(entries []byte) string {
	sum := sha256.Sum256(entries)
	return hex.EncodeToString(sum[:])
}

// LoadDir reads an extracted package and checks that entries.json agrees with
// package.json.
func LoadDir(dir string) (*Package, error) {
	infoBytes, err := os.ReadFile(filepath.Join(dir, FilePackage))
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(infoBytes, &info); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FilePackage, err)
	}
	if info.Format != Version {
		return nil, fmt.Errorf("package format %d, expected %d", info.Format, Version)
	}
	entries, err := os.ReadFile(filepath.Join(dir, FileEntries))
	if err != nil {
		return nil, err
	}
	if got := ContentHash(entries); got != info.ContentHash {
		return nil, errors.New("content hash does not match package.json")
	}
	return &Package{Info: info, Entries: entries}, nil
}

// GeoIP decodes the entries of a geoip package and checks the counts.
func (p *Package) GeoIP() ([]GeoIPEntry, error) {
	if p.Info.Name != PackageGeoIP {
		return nil, fmt.Errorf("package is %q, not %q", p.Info.Name, PackageGeoIP)
	}
	var entries []GeoIPEntry
	if err := json.Unmarshal(p.Entries, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileEntries, err)
	}
	v4, v6 := 0, 0
	for _, e := range entries {
		v4 += len(e.IPv4)
		v6 += len(e.IPv6)
	}
	if err := p.checkCounts(len(entries), v4, v6); err != nil {
		return nil, err
	}
	return entries, nil
}

// ASN decodes the entries of an asn package and checks the counts.
func (p *Package) ASN() ([]ASNEntry, error) {
	if p.Info.Name != PackageASN {
		return nil, fmt.Errorf("package is %q, not %q", p.Info.Name, PackageASN)
	}
	var entries []ASNEntry
	if err := json.Unmarshal(p.Entries, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileEntries, err)
	}
	v4, v6 := 0, 0
	for _, e := range entries {
		v4 += len(e.IPv4)
		v6 += len(e.IPv6)
	}
	if err := p.checkCounts(len(entries), v4, v6); err != nil {
		return nil, err
	}
	return entries, nil
}

func (p *Package) checkCounts(entries, v4, v6 int) error {
	if entries != p.Info.Entries || v4 != p.Info.IPv4Prefixes || v6 != p.Info.IPv6Prefixes {
		return fmt.Errorf("counts do not match package.json: %d entries, %d ipv4, %d ipv6",
			entries, v4, v6)
	}
	return nil
}
