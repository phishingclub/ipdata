package main

import (
	"fmt"
	"math"

	"github.com/phishingclub/ipdata/format"
)

// floor is the smallest record count a package may have. An upstream archive
// that is empty or truncated fails here instead of being published.
type floor struct {
	ipv4   int
	ipv6   int
	values int
}

var floors = map[string]floor{
	format.PackageGeoIP: {ipv4: 100_000, ipv6: 30_000, values: 200},
	format.PackageASN:   {ipv4: 250_000, ipv6: 50_000, values: 50_000},
}

// maxDropped is how many reserved or unparsable prefixes a dataset may contain
// before the upstream data is considered broken
const maxDropped = 100

// check compares a built package against the floors and, when a previous
// manifest is known, against the previous record counts
func check(name string, ds *dataset, b *built, prev *format.ManifestPackage, maxDrift float64) error {
	f, ok := floors[name]
	if !ok {
		return fmt.Errorf("no floor defined for package %s", name)
	}
	if b.count4 < f.ipv4 {
		return fmt.Errorf("%s: %d ipv4 records, floor is %d", name, b.count4, f.ipv4)
	}
	if b.count6 < f.ipv6 {
		return fmt.Errorf("%s: %d ipv6 records, floor is %d", name, b.count6, f.ipv6)
	}
	if b.nvals < f.values {
		return fmt.Errorf("%s: %d values, floor is %d", name, b.nvals, f.values)
	}
	if ds.dropped > maxDropped {
		return fmt.Errorf("%s: dropped %d prefixes, limit is %d", name, ds.dropped, maxDropped)
	}
	if prev == nil {
		return nil
	}
	for _, c := range []struct {
		what     string
		now, was int
	}{
		{"ipv4 records", b.count4, prev.IPv4Records},
		{"ipv6 records", b.count6, prev.IPv6Records},
		{"values", b.nvals, prev.Values},
	} {
		if c.was == 0 {
			continue
		}
		drift := math.Abs(float64(c.now-c.was)) / float64(c.was)
		if drift > maxDrift {
			return fmt.Errorf("%s: %s went from %d to %d (%.0f%%), limit is %.0f%%",
				name, c.what, c.was, c.now, drift*100, maxDrift*100)
		}
	}
	return nil
}
