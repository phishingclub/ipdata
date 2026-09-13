// Package format describes the package files produced by ipdata and read by
// Phishing Club. It has no dependencies outside the standard library so it can
// be copied as is into the consumer.
//
// A package is a tar.gz holding four files:
//
//	package.json  metadata, see Info
//	ipv4.bin      fixed width records, 9 bytes each, see Record4
//	ipv6.bin      fixed width records, 21 bytes each, see Record6
//	values.json   what a record value points to, see the README
//
// Records are sorted by address, then prefix length, then value. The same
// prefix can appear more than once with different values when several entities
// announce it, so a lookup should collect every record that matches the
// longest prefix.
package format

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

const (
	// Version is the format version written to package.json and manifest.json.
	Version = 1

	RecordSize4 = 4 + 1 + 4
	RecordSize6 = 16 + 1 + 4

	FilePackage = "package.json"
	FileIPv4    = "ipv4.bin"
	FileIPv6    = "ipv6.bin"
	FileValues  = "values.json"

	PackageGeoIP = "geoip"
	PackageASN   = "asn"
)

// Record4 is one IPv4 prefix. Value is an index into values.json.
type Record4 struct {
	Addr      [4]byte
	PrefixLen uint8
	Value     uint32
}

// Record6 is one IPv6 prefix. Value is an index into values.json.
type Record6 struct {
	Addr      [16]byte
	PrefixLen uint8
	Value     uint32
}

// Prefix returns the record as a netip.Prefix.
func (r Record4) Prefix() netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4(r.Addr), int(r.PrefixLen))
}

// Prefix returns the record as a netip.Prefix.
func (r Record6) Prefix() netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom16(r.Addr), int(r.PrefixLen))
}

// Info is the content of package.json.
type Info struct {
	Format      int    `json:"format"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Created     string `json:"created"`
	Source      string `json:"source"`
	License     string `json:"license"`
	IPv4Records int    `json:"ipv4_records"`
	IPv6Records int    `json:"ipv6_records"`
	Values      int    `json:"values"`
	ContentHash string `json:"content_hash"`
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
	File        string `json:"file"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentHash string `json:"content_hash"`
	IPv4Records int    `json:"ipv4_records"`
	IPv6Records int    `json:"ipv6_records"`
	Values      int    `json:"values"`
}

// GeoIPValue is one entry of values.json in the geoip package.
type GeoIPValue struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// ASNValue is one entry of values.json in the asn package.
type ASNValue struct {
	ASN     uint32 `json:"asn"`
	Handle  string `json:"handle"`
	Name    string `json:"name"`
	Country string `json:"country"`
}

// Package is a package loaded from disk.
type Package struct {
	Info   Info
	IPv4   []Record4
	IPv6   []Record6
	Values json.RawMessage
}

// EncodeIPv4 serializes records into the ipv4.bin layout.
func EncodeIPv4(records []Record4) []byte {
	out := make([]byte, 0, len(records)*RecordSize4)
	for _, r := range records {
		out = append(out, r.Addr[:]...)
		out = append(out, r.PrefixLen)
		out = binary.BigEndian.AppendUint32(out, r.Value)
	}
	return out
}

// EncodeIPv6 serializes records into the ipv6.bin layout.
func EncodeIPv6(records []Record6) []byte {
	out := make([]byte, 0, len(records)*RecordSize6)
	for _, r := range records {
		out = append(out, r.Addr[:]...)
		out = append(out, r.PrefixLen)
		out = binary.BigEndian.AppendUint32(out, r.Value)
	}
	return out
}

// DecodeIPv4 parses the ipv4.bin layout.
func DecodeIPv4(b []byte) ([]Record4, error) {
	if len(b)%RecordSize4 != 0 {
		return nil, fmt.Errorf("ipv4 data length %d is not a multiple of %d", len(b), RecordSize4)
	}
	records := make([]Record4, len(b)/RecordSize4)
	for i := range records {
		off := i * RecordSize4
		copy(records[i].Addr[:], b[off:off+4])
		records[i].PrefixLen = b[off+4]
		records[i].Value = binary.BigEndian.Uint32(b[off+5 : off+9])
		if records[i].PrefixLen > 32 {
			return nil, fmt.Errorf("ipv4 record %d has prefix length %d", i, records[i].PrefixLen)
		}
	}
	return records, nil
}

// DecodeIPv6 parses the ipv6.bin layout.
func DecodeIPv6(b []byte) ([]Record6, error) {
	if len(b)%RecordSize6 != 0 {
		return nil, fmt.Errorf("ipv6 data length %d is not a multiple of %d", len(b), RecordSize6)
	}
	records := make([]Record6, len(b)/RecordSize6)
	for i := range records {
		off := i * RecordSize6
		copy(records[i].Addr[:], b[off:off+16])
		records[i].PrefixLen = b[off+16]
		records[i].Value = binary.BigEndian.Uint32(b[off+17 : off+21])
		if records[i].PrefixLen > 128 {
			return nil, fmt.Errorf("ipv6 record %d has prefix length %d", i, records[i].PrefixLen)
		}
	}
	return records, nil
}

// ContentHash hashes the data files only, so it stays the same across builds
// when the upstream data did not change.
func ContentHash(ipv4, ipv6, values []byte) string {
	h := sha256.New()
	h.Write(ipv4)
	h.Write(ipv6)
	h.Write(values)
	return hex.EncodeToString(h.Sum(nil))
}

// LoadDir reads an extracted package and checks that the files agree with
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
	ipv4Bytes, err := os.ReadFile(filepath.Join(dir, FileIPv4))
	if err != nil {
		return nil, err
	}
	ipv6Bytes, err := os.ReadFile(filepath.Join(dir, FileIPv6))
	if err != nil {
		return nil, err
	}
	values, err := os.ReadFile(filepath.Join(dir, FileValues))
	if err != nil {
		return nil, err
	}
	if got := ContentHash(ipv4Bytes, ipv6Bytes, values); got != info.ContentHash {
		return nil, errors.New("content hash does not match package.json")
	}
	ipv4, err := DecodeIPv4(ipv4Bytes)
	if err != nil {
		return nil, err
	}
	ipv6, err := DecodeIPv6(ipv6Bytes)
	if err != nil {
		return nil, err
	}
	if len(ipv4) != info.IPv4Records || len(ipv6) != info.IPv6Records {
		return nil, errors.New("record counts do not match package.json")
	}
	var count []json.RawMessage
	if err := json.Unmarshal(values, &count); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileValues, err)
	}
	if len(count) != info.Values {
		return nil, errors.New("value count does not match package.json")
	}
	for i, r := range ipv4 {
		if int(r.Value) >= len(count) {
			return nil, fmt.Errorf("ipv4 record %d points outside values", i)
		}
	}
	for i, r := range ipv6 {
		if int(r.Value) >= len(count) {
			return nil, fmt.Errorf("ipv6 record %d points outside values", i)
		}
	}
	return &Package{Info: info, IPv4: ipv4, IPv6: ipv6, Values: values}, nil
}
