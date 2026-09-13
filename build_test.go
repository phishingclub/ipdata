package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/phishingclub/ipdata/format"
)

// makeTar builds a small gzip compressed tar in memory
func makeTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestParseCountries(t *testing.T) {
	archive := makeTar(t, map[string]string{
		"country/dk/aggregated.json":     `{"country":"Denmark","countryCode":"DK","prefixes":{"ipv4":["2.104.0.0/13","10.0.0.0/8","5.33.0.1/16"],"ipv6":["2a01:4f8::/32"]}}`,
		"country/ad/aggregated.json":     `{"country":"Andorra","countryCode":"AD","prefixes":{"ipv4":["85.94.160.0/19"],"ipv6":[]}}`,
		"country/dk/ipv4-aggregated.txt": "ignored",
		"README.md":                      "ignored",
	})
	ds, err := parseCountries(bytes.NewReader(archive), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.entries) != 2 {
		t.Fatalf("entries: %d", len(ds.entries))
	}
	if ds.dropped != 1 {
		t.Fatalf("dropped %d, want 1 for the private range", ds.dropped)
	}
	if ds.normalized != 1 {
		t.Fatalf("normalized %d, want 1 for the prefix with host bits", ds.normalized)
	}
	b, err := ds.build()
	if err != nil {
		t.Fatal(err)
	}
	r4, err := format.DecodeIPv4(b.ipv4)
	if err != nil {
		t.Fatal(err)
	}
	// AD sorts before DK so AD is value 0 and its 85.x prefix sorts last
	want := []string{"2.104.0.0/13", "5.33.0.0/16", "85.94.160.0/19"}
	wantValue := []uint32{1, 1, 0}
	if len(r4) != len(want) {
		t.Fatalf("ipv4 records: %d", len(r4))
	}
	for i, r := range r4 {
		if r.Prefix().String() != want[i] || r.Value != wantValue[i] {
			t.Fatalf("record %d: %s value %d", i, r.Prefix(), r.Value)
		}
	}
	var values []format.GeoIPValue
	if err := json.Unmarshal(b.values, &values); err != nil {
		t.Fatal(err)
	}
	if values[0].Code != "AD" || values[1].Code != "DK" || values[1].Name != "Denmark" {
		t.Fatalf("values: %+v", values)
	}
}

func TestParseASNs(t *testing.T) {
	archive := makeTar(t, map[string]string{
		"as/15169/aggregated.json": `{"asn":15169,"metadata":{"handle":"GOOGLE","description":"Google LLC","countryCode":"US"},"prefixes":{"ipv4":["8.8.8.0/24"],"ipv6":["2001:4860::/32"]}}`,
		"as/3/aggregated.json":     `{"asn":3,"metadata":{"handle":"AS3","description":"Adaptive Systems A/S","countryCode":"US"},"prefixes":{"ipv4":["8.8.8.0/24"],"ipv6":[]}}`,
	})
	ds, err := parseASNs(bytes.NewReader(archive), "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ds.build()
	if err != nil {
		t.Fatal(err)
	}
	r4, err := format.DecodeIPv4(b.ipv4)
	if err != nil {
		t.Fatal(err)
	}
	// the same prefix is kept once per announcing system, ordered by value
	if len(r4) != 2 || r4[0].Value != 0 || r4[1].Value != 1 {
		t.Fatalf("records: %+v", r4)
	}
	var values []format.ASNValue
	if err := json.Unmarshal(b.values, &values); err != nil {
		t.Fatal(err)
	}
	if values[0].ASN != 3 || values[1].ASN != 15169 || values[1].Name != "Google LLC" {
		t.Fatalf("values: %+v", values)
	}
}

func TestParseASNsRejectsPathMismatch(t *testing.T) {
	archive := makeTar(t, map[string]string{
		"as/15169/aggregated.json": `{"asn":15170,"metadata":{},"prefixes":{"ipv4":[],"ipv6":[]}}`,
	})
	if _, err := parseASNs(bytes.NewReader(archive), "test"); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestCheckFloorsAndDrift(t *testing.T) {
	small := &built{count4: 10, count6: 10, nvals: 10}
	if err := check(format.PackageGeoIP, &dataset{}, small, nil, 0.25); err == nil {
		t.Fatal("expected floor error")
	}
	big := &built{count4: 200_000, count6: 70_000, nvals: 240}
	if err := check(format.PackageGeoIP, &dataset{}, big, nil, 0.25); err != nil {
		t.Fatal(err)
	}
	prev := &format.ManifestPackage{IPv4Records: 100_000, IPv6Records: 70_000, Values: 240}
	if err := check(format.PackageGeoIP, &dataset{}, big, prev, 0.25); err == nil {
		t.Fatal("expected drift error")
	}
	if err := check(format.PackageGeoIP, &dataset{dropped: maxDropped + 1}, big, nil, 0.25); err == nil {
		t.Fatal("expected dropped error")
	}
}

func TestWritePackageLoadsBack(t *testing.T) {
	archive := makeTar(t, map[string]string{
		"country/dk/aggregated.json": `{"country":"Denmark","countryCode":"DK","prefixes":{"ipv4":["2.104.0.0/13"],"ipv6":["2a01:4f8::/32"]}}`,
	})
	ds, err := parseCountries(bytes.NewReader(archive), "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ds.build()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	info := format.Info{
		Format: format.Version, Name: format.PackageGeoIP, Version: "test",
		IPv4Records: b.count4, IPv6Records: b.count6, Values: b.nvals,
		ContentHash: format.ContentHash(b.ipv4, b.ipv6, b.values),
	}
	entry, err := writePackage(out, info, b)
	if err != nil {
		t.Fatal(err)
	}
	// same input must give the same bytes
	again, err := writePackage(t.TempDir(), info, b)
	if err != nil {
		t.Fatal(err)
	}
	if entry.SHA256 != again.SHA256 {
		t.Fatal("package bytes are not reproducible")
	}

	// extract like a consumer would and load with the format package
	f, err := os.Open(filepath.Join(out, entry.File))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	extracted := t.TempDir()
	err = walkTar(f, func(path string, body io.Reader) error {
		data, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(extracted, filepath.Base(path)), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := format.LoadDir(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.IPv4) != 1 || len(pkg.IPv6) != 1 || pkg.Info.Name != format.PackageGeoIP {
		t.Fatalf("loaded: %+v", pkg.Info)
	}
}
