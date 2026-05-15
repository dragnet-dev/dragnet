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
                                        # IOC feeds, STIX 2.1, and incidents/index.json
dragnet update-popular                  # refresh the "popular packages" baseline
                                        # (download counts, used to score impact)
```

A typical end-to-end run is `validate → sync → enrich → generate`. The cron
in `dragnet-dev/haul/.github/workflows/sync.yml` runs exactly that on a
6-hour cycle.

---

## Sources (selection)

OSV · GHSA · NVD · CISA KEV · MSRC · OSSF malicious-packages · npm / PyPI /
cargo / maven registries · MITRE ATT&CK · Trivy DB · Hugging Face ·
AttackerKB · deps.dev · Snyk · VulnCheck · Docker Hub · ransomware.live ·
~30 vendor security blogs.

Some sources require API keys — set them in the environment:

| Variable               | Source                  |
|------------------------|-------------------------|
| `GITHUB_TOKEN`         | `actions/setup-go` rate limits, GHSA, GitHub Actions SHA monitor |
| `ATTACKERKB_API_KEY`   | AttackerKB extended results (optional; rate-limited subset works without) |

---

## Backends

Sigma rules are compiled to: KQL/Sentinel · Splunk · Elastic · Wazuh ·
Chronicle · Suricata · Snort · CrowdStrike (LogScale + IOC) · QRadar ·
Datadog. See `internal/backends/registry.go`.

---

## Output shape

`dragnet generate` writes into the working directory using the layout that
[haul](https://github.com/dragnet-dev/haul) expects:

```
{module}/
  incidents/index.json     # IncidentIndex consumed by port + buoy + scope + trawl
  rules/sigma/             # Source Sigma rules
  rules/{backend}/         # Compiled per-backend rules
  feeds/                   # IOC feeds (domains.txt, ips.txt, sha256.txt, unified.json, stix.json)
incidents/index.json       # Cross-module RootIndex
```

The JSON shape is owned by `internal/index/generator.go`. Downstream
consumers (notably `port/src/types.ts`) mirror it; a CI fixture round-trips
a real `index.json` through the TS types to catch drift.

---

## Build

```bash
go build ./...
go test  ./...
go build -o dragnet .         # the CLI binary (gitignored — `make` it locally or grab a release)
```

The compiled binary is **never committed**; release artefacts come from
`.github/workflows/build.yml` on `v*` tags (linux/amd64, darwin/{amd64,arm64},
windows/amd64).

---

## Configuration

`dragnet.yaml.example` is the documented template. Copy it to `dragnet.yaml`
locally for dev runs. The live config used by `haul`'s sync workflow lives
at [`dragnet-dev/haul/dragnet.yaml`](https://github.com/dragnet-dev/haul/blob/main/dragnet.yaml).

`dragnet.yaml` itself is gitignored — only `.example` ships from this repo.

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
cmd/         Cobra subcommands (sync, generate, validate, enrich, update-popular)
internal/
  sources/   ~70 source-specific clients implementing sources.Source
  backends/  ~11 SIEM backends implementing backends.Backend
  sigma/     Sigma rule generator (canonical IOC normaliser)
  iocutil/   Shared IOC cleaner (used by sources + sigma)
  incident/  Canonical schema + YAML loader/merger
  ioc/       IOC export formats (text, JSON, STIX)
  index/     index.json generator (consumed by port/buoy/scope/trawl)
  enrichment/ Cross-domain actor + shared-IOC linking
  actor/     ATT&CK actor profile store
  confidence/ Source-quality confidence scoring
  container/ Container-specific tiering (Trivy + EOL + KEV)
  popularity/ Package popularity + impact rating
  state/     Incremental sync state
  stix/      STIX 2.1 bundle builder
  typosquat/ Typosquat candidate detection
  deconflict/ IOC allowlists (private IPs, well-known domains)
schema/      JSON Schema for incidents (embed.go vendored at runtime)
```

## License

MIT — see [LICENSE](./LICENSE).
