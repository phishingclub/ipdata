// ipdata turns the ipverse country and autonomous system datasets into
// packages that Phishing Club can download and load as they are.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phishingclub/ipdata/format"
)

const (
	defaultCountryURL = "https://github.com/ipverse/country-ip-blocks/releases/download/latest/country-ip-blocks.tar.gz"
	defaultASNURL     = "https://github.com/ipverse/as-ip-blocks/releases/download/latest/as-ip-blocks.tar.gz"
	upstreamLicense   = "CC0-1.0"

	// maxDownload caps an upstream download. The archives are 2 MB and 17 MB
	// today, so this only stops runaway responses.
	maxDownload = 256 << 20
)

type source struct {
	name  string
	url   string
	file  string
	parse func(io.Reader, string) (*dataset, error)
}

func main() {
	out := flag.String("out", "dist", "output directory")
	countryURL := flag.String("country-url", defaultCountryURL, "upstream country archive")
	asnURL := flag.String("asn-url", defaultASNURL, "upstream autonomous system archive")
	countryFile := flag.String("country-file", "", "use this local country archive instead of downloading")
	asnFile := flag.String("asn-file", "", "use this local autonomous system archive instead of downloading")
	previous := flag.String("previous", "", "manifest.json of the previous release, enables drift checks and change detection")
	version := flag.String("version", time.Now().UTC().Format("2006.01.02-1504"), "version written to the manifest")
	maxDrift := flag.Float64("max-drift", 0.25, "largest allowed change in counts against the previous release")
	downloads := flag.String("downloads", "", "keep downloaded archives in this directory instead of a temp dir")
	flag.Parse()

	if err := run(*out, *version, *previous, *downloads, *maxDrift, []source{
		{format.PackageGeoIP, *countryURL, *countryFile, parseCountries},
		{format.PackageASN, *asnURL, *asnFile, parseASNs},
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(out, version, previous, downloads string, maxDrift float64, sources []source) error {
	var prev *format.Manifest
	if previous != "" {
		data, err := os.ReadFile(previous)
		if err != nil {
			return fmt.Errorf("read previous manifest: %w", err)
		}
		prev = &format.Manifest{}
		if err := json.Unmarshal(data, prev); err != nil {
			return fmt.Errorf("parse previous manifest: %w", err)
		}
		if prev.Format != format.Version {
			fmt.Printf("previous manifest has format %d, this build writes format %d, treating all packages as changed\n", prev.Format, format.Version)
			prev = nil
		}
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if downloads == "" {
		tmp, err := os.MkdirTemp("", "ipdata-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		downloads = tmp
	} else if err := os.MkdirAll(downloads, 0o755); err != nil {
		return err
	}

	created := time.Now().UTC().Format(time.RFC3339)
	manifest := format.Manifest{
		Format:   format.Version,
		Version:  version,
		Created:  created,
		Packages: map[string]format.ManifestPackage{},
	}
	changed := prev == nil
	var summary strings.Builder
	fmt.Fprintf(&summary, "## ipdata %s\n\n", version)

	for _, s := range sources {
		path := s.file
		if path == "" {
			path = filepath.Join(downloads, s.name+"-upstream.tar.gz")
			fmt.Printf("%s: downloading %s\n", s.name, s.url)
			if err := download(s.url, path); err != nil {
				return fmt.Errorf("%s: %w", s.name, err)
			}
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		ds, err := s.parse(f, s.url)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: parse: %w", s.name, err)
		}
		b, err := ds.build()
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}

		var prevPkg *format.ManifestPackage
		if prev != nil {
			if p, ok := prev.Packages[s.name]; ok {
				prevPkg = &p
			}
		}
		if err := check(s.name, ds, b, prevPkg, maxDrift); err != nil {
			return err
		}

		info := format.Info{
			Format:       format.Version,
			Name:         s.name,
			Version:      version,
			Created:      created,
			Source:       s.url,
			License:      upstreamLicense,
			Entries:      b.nvals,
			IPv4Prefixes: b.count4,
			IPv6Prefixes: b.count6,
			ContentHash:  format.ContentHash(b.entries),
		}
		entry, err := writePackage(out, info, b)
		if err != nil {
			return fmt.Errorf("%s: write: %w", s.name, err)
		}
		manifest.Packages[s.name] = entry

		pkgChanged := prevPkg == nil || prevPkg.ContentHash != entry.ContentHash
		if pkgChanged {
			changed = true
		}
		fmt.Printf("%s: %d entries, %d ipv4, %d ipv6, dropped %d, normalized %d, %d bytes, changed=%v\n",
			s.name, b.nvals, b.count4, b.count6, ds.dropped, ds.normalized, entry.Size, pkgChanged)
		fmt.Fprintf(&summary, "- **%s**: %d entries, %d IPv4 prefixes, %d IPv6 prefixes, %.1f MB, changed: %v\n",
			s.name, b.nvals, b.count4, b.count6, float64(entry.Size)/1e6, pkgChanged)
	}

	if err := writeJSON(filepath.Join(out, "manifest.json"), manifest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "changed"), []byte(fmt.Sprintf("%v\n", changed)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(&summary, "\nSource: ipverse, license %s\n", upstreamLicense)
	if err := os.WriteFile(filepath.Join(out, "summary.md"), []byte(summary.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("manifest written to %s, changed=%v\n", filepath.Join(out, "manifest.json"), changed)
	return nil
}

// download fetches url into dest, retrying once on a failed transfer
func download(url, dest string) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(10 * time.Second)
		}
		lastErr = downloadOnce(url, dest)
		if lastErr == nil {
			return nil
		}
		fmt.Printf("download failed: %v\n", lastErr)
	}
	return lastErr
}

func downloadOnce(url, dest string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "phishingclub-ipdata")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxDownload {
		return fmt.Errorf("download exceeds %d bytes", maxDownload)
	}
	return nil
}
