package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"

	"github.com/phishingclub/ipdata/format"
)

// entry is one country or one autonomous system with its prefixes
type entry struct {
	code    string
	asn     uint32
	name    string
	handle  string
	country string
	v4      []netip.Prefix
	v6      []netip.Prefix
}

// dataset is a parsed upstream tarball before it is turned into a package
type dataset struct {
	name       string
	source     string
	entries    []entry
	dropped    int
	normalized int
}

// built is a dataset turned into the content of entries.json
type built struct {
	entries []byte
	count4  int
	count6  int
	nvals   int
}

var (
	countryPath = regexp.MustCompile(`^(?:\./)?country/([a-z]{2})/aggregated\.json$`)
	asnPath     = regexp.MustCompile(`^(?:\./)?as/([0-9]+)/aggregated\.json$`)
)

type countryJSON struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Prefixes    struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	} `json:"prefixes"`
}

type asnJSON struct {
	ASN      uint32 `json:"asn"`
	Metadata struct {
		Handle      string `json:"handle"`
		Description string `json:"description"`
		CountryCode string `json:"countryCode"`
	} `json:"metadata"`
	Prefixes struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	} `json:"prefixes"`
}

// parseCountries reads the ipverse country tarball
func parseCountries(r io.Reader, source string) (*dataset, error) {
	ds := &dataset{name: format.PackageGeoIP, source: source}
	err := walkTar(r, func(path string, body io.Reader) error {
		m := countryPath.FindStringSubmatch(path)
		if m == nil {
			return nil
		}
		var c countryJSON
		if err := json.NewDecoder(body).Decode(&c); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if len(c.CountryCode) != 2 {
			return fmt.Errorf("%s: country code %q", path, c.CountryCode)
		}
		e := entry{code: c.CountryCode, name: c.Country}
		ds.addPrefixes(&e, c.Prefixes.IPv4, c.Prefixes.IPv6)
		ds.entries = append(ds.entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// parseASNs reads the ipverse autonomous system tarball
func parseASNs(r io.Reader, source string) (*dataset, error) {
	ds := &dataset{name: format.PackageASN, source: source}
	err := walkTar(r, func(path string, body io.Reader) error {
		m := asnPath.FindStringSubmatch(path)
		if m == nil {
			return nil
		}
		var a asnJSON
		if err := json.NewDecoder(body).Decode(&a); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fromPath, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil || uint32(fromPath) != a.ASN {
			return fmt.Errorf("%s: asn %d does not match the path", path, a.ASN)
		}
		e := entry{
			asn:     a.ASN,
			handle:  a.Metadata.Handle,
			name:    a.Metadata.Description,
			country: a.Metadata.CountryCode,
		}
		ds.addPrefixes(&e, a.Prefixes.IPv4, a.Prefixes.IPv6)
		ds.entries = append(ds.entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// addPrefixes parses the upstream strings, drops reserved ranges and masks
// any prefix that has host bits set
func (ds *dataset) addPrefixes(e *entry, v4, v6 []string) {
	for _, list := range [][]string{v4, v6} {
		for _, s := range list {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				ds.dropped++
				continue
			}
			if p.Masked() != p {
				p = p.Masked()
				ds.normalized++
			}
			if isReserved(p.Addr()) {
				ds.dropped++
				continue
			}
			if p.Addr().Is4() {
				e.v4 = append(e.v4, p)
			} else {
				e.v6 = append(e.v6, p)
			}
		}
	}
}

func isReserved(a netip.Addr) bool {
	return a.Is4In6() ||
		a.IsUnspecified() ||
		a.IsLoopback() ||
		a.IsPrivate() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() ||
		a.IsMulticast()
}

// build sorts the entries and their prefixes and writes entries.json with one
// entry per line
func (ds *dataset) build() (*built, error) {
	if len(ds.entries) == 0 {
		return nil, errors.New("no entries found in the upstream archive")
	}
	sort.Slice(ds.entries, func(i, j int) bool {
		a, b := ds.entries[i], ds.entries[j]
		if a.code != b.code {
			return a.code < b.code
		}
		return a.asn < b.asn
	})
	for i := 1; i < len(ds.entries); i++ {
		a, b := ds.entries[i-1], ds.entries[i]
		if a.code == b.code && a.asn == b.asn {
			return nil, fmt.Errorf("duplicate entry %s%d", a.code, a.asn)
		}
	}

	var out bytes.Buffer
	out.WriteString("[\n")
	b := &built{nvals: len(ds.entries)}
	for i, e := range ds.entries {
		v4 := sortedStrings(e.v4)
		v6 := sortedStrings(e.v6)
		b.count4 += len(v4)
		b.count6 += len(v6)
		var v any
		if ds.name == format.PackageGeoIP {
			v = format.GeoIPEntry{Code: e.code, Name: e.name, IPv4: v4, IPv6: v6}
		} else {
			v = format.ASNEntry{ASN: e.asn, Handle: e.handle, Name: e.name, Country: e.country, IPv4: v4, IPv6: v6}
		}
		line, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out.Write(line)
		if i < len(ds.entries)-1 {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("]\n")
	b.entries = out.Bytes()
	return b, nil
}

// sortedStrings orders prefixes by address then prefix length and returns
// them as strings, never nil so the JSON holds an empty array
func sortedStrings(prefixes []netip.Prefix) []string {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// walkTar calls fn for every regular file in a gzip compressed tar stream
func walkTar(r io.Reader, fn func(path string, body io.Reader) error) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := fn(hdr.Name, tr); err != nil {
			return err
		}
	}
}
