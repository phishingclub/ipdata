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
30 releases and deletes older ones. After publishing it commits the manifest
to `latest/manifest.json` on the branch. That commit is what keeps the daily
schedule running, GitHub disables cron in a repository with no pushes for 60
days.

The repository must be public. The download URLs above require authentication
on a private repository, so instances could not fetch anything.

A push to the `test-build` branch runs the whole build and keeps the output as
a workflow artifact without publishing. A manual run from the Actions tab can
also be told not to publish.

## Package layout

Each package is a tar.gz with two JSON files at the top level, so anyone can
open it and read it with `jq`, `grep` or a text editor.

`package.json`

```json
{
  "format": 1,
  "name": "geoip",
  "version": "2026.09.13-0417",
  "created": "2026-09-13T04:17:31Z",
  "source": "https://github.com/ipverse/country-ip-blocks/releases/download/latest/country-ip-blocks.tar.gz",
  "license": "CC0-1.0",
  "entries": 238,
  "ipv4_prefixes": 178280,
  "ipv6_prefixes": 69303,
  "content_hash": "sha256 of entries.json"
}
```

`entries.json` is a JSON array with one entry per line. For `geoip` the
entries are countries sorted by code:

```json
[
{"code":"AD","name":"Andorra","ipv4":["45.134.104.0/22","46.172.224.0/19"],"ipv6":["2a02:6d40::/32"]},
{"code":"AE","name":"United Arab Emirates","ipv4":["2.48.0.0/13"],"ipv6":["2001:8f8::/32"]}
]
```

For `asn` the entries are autonomous systems sorted by number:

```json
[
{"asn":3,"handle":"AS3","name":"Adaptive Systems A/S","country":"US","ipv4":["18.2.0.0/16"],"ipv6":[]},
{"asn":15169,"handle":"GOOGLE","name":"Google LLC","country":"US","ipv4":["8.8.8.0/24"],"ipv6":["2001:4860::/32"]}
]
```

Prefixes inside an entry are sorted by address. The same prefix can appear in
more than one ASN entry when several systems announce it, so a lookup should
collect every entry matching the longest prefix. Reserved and private ranges
are removed at build time, and a prefix with host bits set is masked.

`manifest.json` in a release lists both packages with their file name, size,
sha256 of the archive, the content hash, and the counts. A consumer that
stored the content hash of what it installed can compare it against the
manifest to know whether an update is available.

The `format` package in this repository reads a package with `LoadDir`, checks
the content hash against `package.json`, and decodes the entries with
`GeoIP()` or `ASN()` while checking the counts. It is standard library only
and meant to be copied into the consumer.

## Checks before publishing

The build fails, and nothing is published, when

- a package has fewer prefixes or entries than a fixed floor,
- more than 100 prefixes had to be dropped as invalid or reserved,
- any count moved more than 25% against the previous release,
- an ASN directory name does not match the number inside its file.

The floors and the drift limit are in `checks.go` and the `-max-drift` flag.

## Running locally

```
go test ./...
go run . -out dist
```

Without a local Go toolchain, the same in the pinned image the phishingclub
build uses:

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
| `-max-drift` | `0.25` | allowed change in counts against the previous release |

Output in `dist/`: `manifest.json`, `geoip.tar.gz`, `asn.tar.gz`, `summary.md`
for the release notes, and `changed` holding `true` or `false`.

From the orchestrator root `make ipdata-build` runs the same command.

## License

This tool is released under CC0 1.0, the same public domain dedication as the
upstream data, so nothing here adds any restriction on top of ipverse. See the
LICENSE file.

The IP data comes from ipverse and is CC0 1.0. The published packages carry
that source and license in their package.json.
