package format

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	v4 := []Record4{
		{Addr: [4]byte{8, 8, 8, 0}, PrefixLen: 24, Value: 1},
		{Addr: [4]byte{10, 0, 0, 0}, PrefixLen: 8, Value: 0},
	}
	v6 := []Record6{
		{Addr: netip.MustParseAddr("2a01:4f8::").As16(), PrefixLen: 32, Value: 1},
	}
	got4, err := DecodeIPv4(EncodeIPv4(v4))
	if err != nil {
		t.Fatal(err)
	}
	got6, err := DecodeIPv6(EncodeIPv6(v6))
	if err != nil {
		t.Fatal(err)
	}
	if len(got4) != 2 || got4[0] != v4[0] || got4[1] != v4[1] {
		t.Fatalf("ipv4 mismatch: %+v", got4)
	}
	if len(got6) != 1 || got6[0] != v6[0] {
		t.Fatalf("ipv6 mismatch: %+v", got6)
	}
	if got4[0].Prefix().String() != "8.8.8.0/24" {
		t.Fatalf("prefix: %s", got4[0].Prefix())
	}
	if got6[0].Prefix().String() != "2a01:4f8::/32" {
		t.Fatalf("prefix: %s", got6[0].Prefix())
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	if _, err := DecodeIPv4([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected length error")
	}
	if _, err := DecodeIPv4([]byte{1, 2, 3, 4, 33, 0, 0, 0, 0}); err == nil {
		t.Fatal("expected prefix length error")
	}
	if _, err := DecodeIPv6(make([]byte, RecordSize6+1)); err == nil {
		t.Fatal("expected length error")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	v4 := EncodeIPv4([]Record4{{Addr: [4]byte{1, 2, 3, 0}, PrefixLen: 24, Value: 0}})
	v6 := EncodeIPv6(nil)
	values, _ := json.Marshal([]GeoIPValue{{Code: "DK", Name: "Denmark"}})
	info := Info{
		Format:      Version,
		Name:        PackageGeoIP,
		IPv4Records: 1,
		IPv6Records: 0,
		Values:      1,
		ContentHash: ContentHash(v4, v6, values),
	}
	infoBytes, _ := json.Marshal(info)
	for name, data := range map[string][]byte{
		FilePackage: infoBytes, FileIPv4: v4, FileIPv6: v6, FileValues: values,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.IPv4) != 1 || pkg.Info.Name != PackageGeoIP {
		t.Fatalf("unexpected package: %+v", pkg.Info)
	}

	// a value index outside values.json must be rejected
	bad := EncodeIPv4([]Record4{{Addr: [4]byte{1, 2, 3, 0}, PrefixLen: 24, Value: 5}})
	info.ContentHash = ContentHash(bad, v6, values)
	infoBytes, _ = json.Marshal(info)
	os.WriteFile(filepath.Join(dir, FileIPv4), bad, 0o644)
	os.WriteFile(filepath.Join(dir, FilePackage), infoBytes, 0o644)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected out of range value error")
	}

	// a changed data file must fail the content hash check
	os.WriteFile(filepath.Join(dir, FileIPv4), v4, 0o644)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected content hash error")
	}
}
