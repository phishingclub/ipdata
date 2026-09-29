package main

import (
	"fmt"
	"math"

	"github.com/phishingclub/ipdata/format"
)

// floor is the smallest count a package may have. An upstream archive that is
// empty or truncated fails here instead of being published.
type floor struct {
	ipv4    int
	ipv6    int
	entries int
}

var floors = map[string]floor{
	format.PackageGeoIP: {ipv4: 100_000, ipv6: 30_000, entries: 200},
	format.PackageASN:   {ipv4: 250_000, ipv6: 50_000, entries: 50_000},
}

// maxDropped is how many reserved or unparsable prefixes a dataset may contain
// before the upstream data is considered broken
const maxDropped = 100

// check compares a built package against the floors and, when a previous
// manifest is known, against the previous counts
func check(name string, ds *dataset, b *built, prev *format.ManifestPackage, maxDrift float64) error {
	f, ok := floors[name]
	if !ok {
		return fmt.Errorf("no floor defined for package %s", name)
	}
	if b.count4 < f.ipv4 {
		return fmt.Errorf("%s: %d ipv4 prefixes, floor is %d", name, b.count4, f.ipv4)
	}
	if b.count6 < f.ipv6 {
		return fmt.Errorf("%s: %d ipv6 prefixes, floor is %d", name, b.count6, f.ipv6)
	}
	if b.nvals < f.entries {
		return fmt.Errorf("%s: %d entries, floor is %d", name, b.nvals, f.entries)
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
		{"ipv4 prefixes", b.count4, prev.IPv4Prefixes},
		{"ipv6 prefixes", b.count6, prev.IPv6Prefixes},
		{"entries", b.nvals, prev.Entries},
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
