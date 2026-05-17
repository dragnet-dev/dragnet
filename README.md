# dragnet

[![CI](https://github.com/dragnet-dev/dragnet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dragnet-dev/dragnet/actions/workflows/ci.yml)
[![Release](https://github.com/dragnet-dev/dragnet/actions/workflows/build.yml/badge.svg)](https://github.com/dragnet-dev/dragnet/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report](https://goreportcard.com/badge/github.com/dragnet-dev/dragnet)](https://goreportcard.com/report/github.com/dragnet-dev/dragnet)
[![Go Reference](https://pkg.go.dev/badge/github.com/dragnet-dev/dragnet.svg)](https://pkg.go.dev/github.com/dragnet-dev/dragnet)
[![Latest release](https://img.shields.io/github/v/release/dragnet-dev/dragnet?logo=github)](https://github.com/dragnet-dev/dragnet/releases)

**The aggregation engine behind [Dragnet](https://dragnet.dev).** Polls ~70
threat-intel sources, deduplicates incidents into a canonical schema, and
generates ready-to-deploy detection rules for every major SIEM plus IOC
feeds and STIX 2.1 bundles.

The output is committed to [dragnet-dev/haul](https://github.com/dragnet-dev/haul)
on a 6-hour cron and consumed by the rest of the org:
[port](https://github.com/dragnet-dev/port) (web UI),
[buoy](https://github.com/dragnet-dev/buoy) (MCP for AI coding agents),
[scope](https://github.com/dragnet-dev/scope) (VS Code extension), and
[trawl](https://github.com/dragnet-dev/trawl) (GitHub Action).

---

## Modules

| Module       | What it covers                                                |
|--------------|---------------------------------------------------------------|
| `supply`     | npm / PyPI / cargo / maven / nuget / rubygems / go / etc.     |
| `malware`    | Loaders, RATs, info-stealers, web shells                      |
| `ransomware` | Active campaigns, leak sites, TTPs                            |
| `cve`        | KEV-listed and exploited CVEs across vendor products          |
| `container`  | Vulnerable base images, EOL Linux distros, Trivy DB tier-2/3  |

---

## Subcommands

```bash
dragnet validate --module all           # validate incident YAMLs against the schema
dragnet sync     --module supply        # poll sources for that module
dragnet enrich   --cross-domain         # link actors / shared IOCs across modules
dragnet generate --module all --backends all --layers all
                                        # emit Sigma rules, compiled SIEM dialects,
                                        # IOC feeds, STIX 2.1, search index,
                                        # and incidents/index.json
dragnet update-popular                  # refresh the "popular packages" baseline
                                        # (download counts, used to score impact)
dragnet manifest --root .               # write feeds/manifest.json (per-file
                                        # records/bytes/sha256 for cache invalidation)
```

A typical end-to-end run is `validate → sync → enrich → generate → manifest`.
The cron in `dragnet-dev/haul/.github/workflows/sync.yml` runs exactly that
on a 6-hour cycle.

---

## Sources (selection)

**Bulk:** OSV (11 ecosystems incl. `GitHub Actions`) · OSSF malicious-packages
(git-clone walk) · CISA KEV (full catalog every run) · NVD (2-year backfill
with API key, 1-year without) · GHSA · ransomware.live (full historical
2020+) · MalwareBazaar / URLhaus (abuse.ch).

**Per-package / registry:** npm · PyPI · cargo · maven · nuget · rubygems ·
go · hex · packagist · pub.

**Vendor blogs (~30):** wiz, socket, aikido, stepsecurity, sonatype, jfrog,
sentinelone, crowdstrike, protectai, unit42, mandiant, securelist, microsoft,
bleepingcomputer, the_hacker_news, krebsonsecurity, dfir_report, elastic_labs,
eset, sekoia, talos, proofpoint, malwarebytes, polyswarm, project_zero,
greynoise, horizon3, tenable, watchtowr, etc.

**Container:** Trivy DB (165k OS-package CVEs across alpine/debian/ubuntu/
amazon/redhat/oracle/suse/photon/azure/wolfi/chainguard) · endoflife.date ·
Docker Hub popularity.

**Intel:** MITRE ATT&CK (174 actor profiles), Hugging Face (model anomaly
detection on top-200 popular models, autobootstrapped on first run).

Trivy CLI is a runtime dependency for the container module — install via
`apt-get install trivy` or equivalent. The bundled trivy-db library walks
the bbolt schema directly.

Some sources require API keys; set them in the environment:

| Variable                       | Source / Effect |
|--------------------------------|-----------------|
| `GITHUB_TOKEN`                 | GHSA + GitHub Actions SHA monitor + rate-limit friendliness on actions/setup-go |
| `NVD_API_KEY`                  | NVD: 50 req/30s + 2-year backfill (vs 5 req/30s + 1-year unkeyed). Free at nvd.nist.gov/developers/request-an-api-key |
| `MALWARE_BAZAAR_AUTH_KEY`      | abuse.ch MalwareBazaar `get_recent` endpoint (returns 401 without). Free at auth.abuse.ch |
| `ATTACKERKB_API_KEY`           | AttackerKB exploit / PoC tracking. Free at attackerkb.com |

Sources without keys gracefully skip with a clear log line — they don't
error the module.

---

## Backends

Sigma rules are compiled to: KQL/Sentinel · Splunk · Elastic · Wazuh ·
Chronicle · Suricata · Snort · CrowdStrike (LogScale + IOC) · QRadar ·
Datadog. See `internal/backends/registry.go`.

---

## Output shape

`dragnet sync` + `dragnet generate` + `dragnet manifest` together write the
following into the working directory (the haul checkout):

```
{module}/
  incidents/
    index.json                       # Curated subset (~5k) for port's main listing
    all/{shard}[-N].jsonl            # Every merged incident, byte-sharded ≤45MB
    drafts/{year}/{id}.yaml          # Pending-triage drafts, year-tier sub-dirs
  lookup/
    by-package.json                  # {"ecosystem/name": [{id, severity, ...}]}
                                     # O(1) lookup for buoy/scope/trawl
  rules/
    sigma/{layer}/{year}/*.yaml      # Source Sigma rules (exposure/ioc/hunting)
    {backend}/                       # Compiled per-backend rules
  feeds/
    domains.txt, ips.txt, sha256.txt # Streamable IOC lines
    unified.json                     # Per-IOC enriched view
    unified.jsonl                    # Same as unified.json, one record per line
    stix/bundle.json                 # Combined STIX 2.1 bundle (curated subset)
feeds/
  manifest.json                      # Per-file records+bytes+sha256, sorted,
                                     # deterministic — for cache invalidation
  search-{module}[-N].jsonl          # Per-module search index, byte-sharded
                                     # (skips Tier-4 container records)
  unified.json + unified.jsonl       # Cross-module combined IOC feed
  stix/bundle.json                   # Cross-module combined STIX bundle
incidents/index.json                 # Cross-module RootIndex
actors/profiles/*.yaml               # MITRE ATT&CK actor records (174 default)
state/                               # Resume cursors + sigma-id registry +
                                     # bootstrap caches (mostly gitignored)
```

The JSON shape is owned by `internal/incident/schema.go` (struct tags
mirror `yaml:` and `json:` so YAMLs and JSONL shards round-trip
identically). Downstream consumers (notably `port/src/types.ts`) mirror it;
a CI fixture round-trips a real `index.json` through the TS types to catch
drift.

### Container module tiering

Container CVEs are bucketed via `internal/container/filter.go`:

| Tier | Selection                                            | Output |
|------|------------------------------------------------------|--------|
| 1    | CISA KEV (actively exploited)                        | Persisted + sigma + IOC + STIX |
| 2    | CVSS ≥ 9.0 on a popular image                        | Persisted + sigma + IOC + STIX |
| 3    | CVSS ≥ 7.0 + public PoC on a popular image           | Persisted + sigma + IOC + STIX |
| 4    | Everything else (~158k Trivy DB records by default)  | Persisted to JSONL shards only |

Tier 4 is the "informational" fallback — full data lives in
`container/incidents/all/*.jsonl` for cross-reference / lookup but doesn't
ship as actionable detection rules. Strict filtering (no Tier 4) kicks in
once you populate `state/popular_images.json` via
`dragnet update-popular --module container`.

---

## Build

```bash
go build ./...
go test  ./...
go build -o dragnet .         # the CLI binary (gitignored; `make` it locally or grab a release)
```

The compiled binary is **never committed**; release artefacts come from
`.github/workflows/build.yml` on `v*` tags (linux/amd64, darwin/{amd64,arm64},
windows/amd64).

---

## Configuration

`dragnet.yaml.example` is the documented template. Copy it to `dragnet.yaml`
locally for dev runs. The live config used by `haul`'s sync workflow lives
at [`dragnet-dev/haul/dragnet.yaml`](https://github.com/dragnet-dev/haul/blob/main/dragnet.yaml).

`dragnet.yaml` itself is gitignored; only `.example` ships from this repo.

---

## Security

- All outbound HTTP uses an SSRF-safe transport for sources that follow
  arbitrary upstream URLs (blog RSS feeds): private/loopback/link-local
  destinations are rejected at the dialer; bodies are capped at 5 MiB. See
  `internal/sources/blogs/client.go`.
- The IOC normaliser (`internal/iocutil`) deconflicts every emitted indicator
  against allowlists for well-known infrastructure (Google DNS, RFC1918,
  vendor sinkhole ranges) before it can land in a generated rule.
- No telemetry, no remote crash reporting, no auth except per-source API keys
  read from env.

Found a security issue? Email security@dragnet.dev.

---

## Repo layout

```
cmd/         Cobra subcommands (sync, generate, validate, enrich,
             update-popular, manifest)
internal/
  sources/   ~50 source-specific clients implementing sources.Source
  backends/  11 SIEM backends implementing backends.Backend
  sigma/     Sigma rule generator (canonical IOC normaliser)
  iocutil/   Shared IOC cleaner (used by sources + sigma)
  incident/  Canonical schema + YAML loader/merger (yaml: + json: tags)
  ioc/       IOC export formats (text, JSON, JSONL, STIX)
  index/     index.json + by-package.json + JSONL shards + search index
  manifest/  feeds/manifest.json builder (deterministic, sha256-stable)
  enrichment/ Cross-domain actor + shared-IOC + CVE_ID linking
  actor/     ATT&CK actor profile store (174 profiles)
  confidence/ Source-quality confidence scoring
  container/ Container-specific tiering (Trivy + EOL + KEV)
  popularity/ Package popularity + impact rating + HF model bootstrap
  state/     Incremental sync state (per-module cursors)
  stix/      STIX 2.1 bundle builder (curated subset, not bulk)
  typosquat/ Typosquat candidate detection
  deconflict/ IOC allowlists (private IPs, well-known domains)
schema/      JSON Schema for incidents (embed.go vendored at runtime)
```

## License

MIT. See [LICENSE](./LICENSE).
