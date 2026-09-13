# ipdata

Builds the Geo IP and ASN packages that a Phishing Club instance can download
from the settings page. The data comes from
[ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) and
[ipverse/as-ip-blocks](https://github.com/ipverse/as-ip-blocks), both public
domain (CC0 1.0), rebuilt daily from the five regional internet registries and
BGP announcements.

The tool downloads the two upstream archives, checks them, and writes packages
in a fixed layout so the consumer only has to download, extract and read.
Standard library only, no dependencies.

## Releases

The GitHub workflow runs every day and on demand. It publishes a release only
when the package content changed since the last release, so the release list
reflects real data changes. Every release carries all three files:

| Asset | What |
|---|---|
| `manifest.json` | what the release holds, one small file to poll |
| `geoip.tar.gz` | prefix to country |
| `asn.tar.gz` | prefix to autonomous system |

Stable URLs, always pointing at the newest release:

```
https://github.com/phishingclub/ipdata/releases/latest/download/manifest.json
https://github.com/phishingclub/ipdata/releases/latest/download/geoip.tar.gz
https://github.com/phishingclub/ipdata/releases/latest/download/asn.tar.gz
```

Releases are tagged `v<YYYY.MM.DD-HHMM>` in UTC. The workflow keeps the newest
30 releases and deletes older ones.

A push to the `test-build` branch runs the whole build and keeps the output as
a workflow artifact without publishing. A manual run from the Actions tab can
also be told not to publish.

## Package layout

Each package is a tar.gz with four files at the top level.

`package.json`

```json
{
  "format": 1,
  "name": "geoip",
  "version": "2026.09.13-0417",
  "created": "2026-09-13T04:17:31Z",
  "source": "https://github.com/ipverse/country-ip-blocks/releases/download/latest/country-ip-blocks.tar.gz",
  "license": "CC0-1.0",
  "ipv4_records": 178280,
  "ipv6_records": 69303,
  "values": 238,
  "content_hash": "sha256 of ipv4.bin, ipv6.bin and values.json concatenated"
}
```

`ipv4.bin` holds fixed width records of 9 bytes, `ipv6.bin` of 21 bytes. All
integers are big endian.

| Field | IPv4 | IPv6 |
|---|---|---|
| address | 4 bytes | 16 bytes |
| prefix length | 1 byte | 1 byte |
| value | 4 bytes | 4 bytes |

`value` is an index into the array in `values.json`. Records are sorted by
address, then prefix length, then value. The same prefix can appear more than
once with different values when several autonomous systems announce it, so a
lookup should collect every record matching the longest prefix. Reserved and
private ranges are removed at build time, and a prefix with host bits set is
masked.

`values.json` for `geoip`, sorted by code:

```json
[{"code":"AD","name":"Andorra"}, {"code":"AE","name":"United Arab Emirates"}]
```

`values.json` for `asn`, sorted by number:

```json
[{"asn":3,"handle":"AS3","name":"Adaptive Systems A/S","country":"US"}]
```

`manifest.json` in a release lists both packages with their file name, size,
sha256 of the archive, the content hash, and the record counts. A consumer that
stored the content hash of what it installed can compare it against the
manifest to know whether an update is available.

The `format` package in this repository reads a package with `LoadDir` and
checks counts and content hash against `package.json`. It is standard library
only and meant to be copied into the consumer.

## Checks before publishing

The build fails, and nothing is published, when

- a package has fewer records or entries than a fixed floor,
- more than 100 prefixes had to be dropped as invalid or reserved,
- any record count moved more than 25% against the previous release,
- an ASN directory name does not match the number inside its file.

The floors and the drift limit are in `checks.go` and the `-max-drift` flag.

## Running locally

```
docker run --rm -v "$PWD:/src" -w /src -e GOFLAGS=-buildvcs=false \
  golang@sha256:c4ea15b4a7912716eb362a022e2b12317762eca387423760bc59c0f9ae69423c \
  go run . -out dist
```

Flags:

| Flag | Default | Purpose |
|---|---|---|
| `-out` | `dist` | output directory |
| `-previous` | | previous `manifest.json`, enables drift checks and change detection |
| `-version` | UTC date and time | version string written to the manifest |
| `-country-file`, `-asn-file` | | use local upstream archives instead of downloading |
| `-downloads` | temp dir | keep the upstream archives here |
| `-max-drift` | `0.25` | allowed change in record counts against the previous release |

Output in `dist/`: `manifest.json`, `geoip.tar.gz`, `asn.tar.gz`, `summary.md`
for the release notes, and `changed` holding `true` or `false`.

From the orchestrator root `make ipdata-build` runs the same command.
