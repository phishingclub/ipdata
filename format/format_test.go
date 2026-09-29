package format

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writePackage(t *testing.T, dir string, info Info, entries []byte) {
	t.Helper()
	infoBytes, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FilePackage), infoBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileEntries), entries, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirGeoIP(t *testing.T) {
	dir := t.TempDir()
	entries := []byte(`[{"code":"DK","name":"Denmark","ipv4":["2.104.0.0/13"],"ipv6":["2a01:4f8::/32","2a02::/16"]}]`)
	info := Info{
		Format:       Version,
		Name:         PackageGeoIP,
		Entries:      1,
		IPv4Prefixes: 1,
		IPv6Prefixes: 2,
		ContentHash:  ContentHash(entries),
	}
	writePackage(t, dir, info, entries)
	pkg, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pkg.GeoIP()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Code != "DK" || got[0].IPv6[1] != "2a02::/16" {
		t.Fatalf("entries: %+v", got)
	}
	if _, err := pkg.ASN(); err == nil {
		t.Fatal("expected wrong package name error")
	}

	// counts in package.json must match the entries
	info.IPv4Prefixes = 2
	writePackage(t, dir, info, entries)
	pkg, err = LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.GeoIP(); err == nil {
		t.Fatal("expected count mismatch error")
	}

	// a changed entries file must fail the content hash check
	info.IPv4Prefixes = 1
	writePackage(t, dir, info, append(entries, '\n'))
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected content hash error")
	}

	// an unknown format version is refused
	info.Format = Version + 1
	writePackage(t, dir, info, entries)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected format version error")
	}
}

func TestLoadDirASN(t *testing.T) {
	dir := t.TempDir()
	entries := []byte(`[{"asn":15169,"handle":"GOOGLE","name":"Google LLC","country":"US","ipv4":["8.8.8.0/24"],"ipv6":[]}]`)
	info := Info{
		Format:       Version,
		Name:         PackageASN,
		Entries:      1,
		IPv4Prefixes: 1,
		ContentHash:  ContentHash(entries),
	}
	writePackage(t, dir, info, entries)
	pkg, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pkg.ASN()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ASN != 15169 || got[0].Name != "Google LLC" {
		t.Fatalf("entries: %+v", got)
	}
}
