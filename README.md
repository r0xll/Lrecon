# LRecon

*Let's Recon* — an external attack-surface recon orchestrator for **authorized** penetration tests.

lrecon wraps best-of-breed passive sources and enrichment APIs into one fast,
async pipeline and produces **report-ready** output — a Markdown deliverable, a
machine-readable JSON, and a live-host URL list you can pipe straight into
`nuclei`/`httpx`. It is opinionated toward netpen workflow rather than being a
generic OSINT graph tool: unique-IP enrichment, enum-quality wildcard filtering,
subdomain-takeover leads, and Cloudflare origin-IP discovery are all findings you
can act on, not noise.

> **Authorized use only.** Every target must be in scope under a signed SOW and
> rules of engagement. See [Legal / ROE](#legal--roe).

## Package layout

```
lrecon/
  cli.py         argparse + driver          core.py      orchestration (run)
  common.py      log, Host, keys, consts    sources.py   passive enum + DNS
  enrich.py      ipinfo/shodan/nvd/favicon  intel.py     cloudflare/email/github/buckets/breach
  active.py      http probe + tcp scan      backends.py  ProjectDiscovery wiring
  state.py       cache + diff               report.py    markdown / html / live / screenshots
```

## ProjectDiscovery backends

lrecon uses PD tools as **optional native accelerators** when their binaries are on
PATH, falling back to pure-Python otherwise (nothing is required):

| Tool | Accelerates | Fallback |
|---|---|---|
| `subfinder` | passive subdomain enum | keyless CT/passive-DNS sources |
| `dnsx` | mass A/AAAA/CNAME resolution | dnspython per-host |
| `httpx` | HTTP probe + tech fingerprint + favicon | built-in probe |
| `naabu` | port scan (`--active-ports`) | async TCP connect scan |
| `nuclei` | templated vuln scan (`--nuclei`) | — (no fallback; skipped if absent) |

Install them (Go):

```fish
go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,dnsx/cmd/dnsx,httpx/cmd/httpx,naabu/v2/cmd/naabu,nuclei/v3/cmd/nuclei}@latest
```

Startup logs which backends are active. `--no-pd` forces pure-Python (reproducible
runs / debugging). Validate the integration before an engagement:

```fish
lrecon --check-backends           # detect binaries + confirm parser mapping (safe/passive)
lrecon --check-backends --check-active   # also let naabu/nuclei test-scan scanme.nmap.org
```

`--check-backends` runs each detected tool and reports whether its output parsed
into the expected fields — if a binary is present but shows `RAN=no`, its output
format has drifted and the parser in `backends.py` needs a key update.

**httpx name collision:** the Python `httpx` library ships its own `httpx` CLI that
shadows ProjectDiscovery's binary inside a venv. LRecon handles this automatically —
it scans PATH *and* Go install locations (`$GOBIN`, `$GOPATH/bin`, `~/go/bin`) and
verifies each candidate via `-version`, so it uses the real PD binary without any
renaming. Override with `LRECON_HTTPX=/path/to/httpx` if yours lives elsewhere.

---

## Pipeline

| Phase | What runs | Target touch |
|---|---|---|
| 1. Passive enum | crt.sh, Cert Spotter, OTX, Anubis, Wayback CDX, Shodan DNS, subfinder | none |
| 2. Resolution | shared fast resolver, A/AAAA/CNAME concurrent, wildcard filtering | DNS only |
| 3. Enrichment | per **unique IP**: IPinfo (ASN/org/rDNS) + Shodan host / InternetDB (ports/CVE) | none (API) |
| 4. Active | HTTP probe, favicon hash, takeover checks, optional TCP scan | yes |
| CF origin | Cloudflare detection + origin-IP candidates (+ optional confirm) | confirm step only |
| Expansion | ASN->netblock (RIPEstat) + reverse-DNS sweep, rDNS wire-back | DNS only |
| Intel | email posture (SPF/DKIM/DMARC), GitHub dorking, cloud buckets, breach, favicon pivot | none / provider |
| CVE | NVD CPE->CVE resolution (opt-in, cached) | none (API) |
| Diff | change vs previous run snapshot | none |

Sources are keyless except **Shodan** and **subfinder**. Shodan/InternetDB only
hold data for IPs they have already indexed, so they are often empty — that is
expected. IPinfo fills ASN/org/rDNS regardless.

---

## Install

Requires Python 3.10+. `subfinder` is optional but recommended (broadens passive
enum). Uses a project venv — no system-package changes.

```fish
git clone <your-repo> ~/tools/lrecon    # package dir with pyproject.toml + lrecon/
cd ~/tools/lrecon

python3 -m venv venv
source venv/bin/activate.fish
pip install -e .                         # installs deps + `lrecon` console command
# optional screenshots (pulls headless chromium):
pip install -e '.[screenshots]'; playwright install chromium
```

Optional, for broader passive enum:

```fish
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Run without activating (cron/scripts):

```fish
~/tools/lrecon/venv/bin/lrecon example.com
```

---

## API keys

Both are optional. Precedence for each: **CLI flag > env var > config file**.

| Service | Purpose | Flag | Env | Free tier |
|---|---|---|---|---|
| Shodan | ports/CVE enrichment, passive DNS, cert search | `--shodan-key` | `SHODAN_API_KEY` | limited |
| IPinfo | ASN / org / reverse-DNS / geo | `--ipinfo-key` | `IPINFO_TOKEN` | 50k/mo |
| GitHub | code dorking for leaked secrets/hostnames | — | `GITHUB_TOKEN` | free |
| HIBP | breach-by-domain (keyless list endpoint) | — | `HIBP_API_KEY` | keyless list |

```fish
# persistent (fish universal vars — visible inside the venv)
set -Ux SHODAN_API_KEY "..."
set -Ux IPINFO_TOKEN   "..."

# or config file
mkdir -p ~/.config/lrecon
echo '{"shodan_api_key":"...","ipinfo_token":"..."}' > ~/.config/lrecon/config.json

# or interactive (stays out of shell history)
lrecon example.com --ask-keys
```

Without a Shodan key, lrecon falls back to keyless **InternetDB** for ports/CVEs.

---

## Usage

```fish
# 1. pure passive — pre-authorization recon, zero packets at the target
lrecon client.com --passive-only -o client_passive

# 2. full recon — resolution, enrichment, HTTP probe, takeover + CF origin checks
lrecon client.com -o client

# 3. add active TCP port confirmation (scope-permitting)
lrecon client.com --active-ports -o client_full
lrecon client.com --active-ports --ports 80,443,8080,8443 -o client_web

# multiple roots + custom resolvers
lrecon client.com client.net --resolvers 1.1.1.1,9.9.9.9 -o client
```

### Handoff to nuclei / httpx

```fish
lrecon client.com -o client
nuclei -l client.live.txt -o client_nuclei.txt
httpx -l client.live.txt -tech-detect -title
```

### Key flags

| Flag | Effect |
|---|---|
| `--passive-only` | OSINT sources + host lookup only; no resolution/HTTP/portscan |
| `--active-ports` | async TCP connect scan of common ports (aggressive; ROE-gated) |
| `--ports a,b,c` | custom port set for `--active-ports` |
| `--no-cf-origin` | disable Cloudflare origin-IP discovery |
| `--asn-expand` | expand scope via ASN->netblocks + reverse-DNS sweep (aggressive) |
| `--asn-cap N` | max PTR lookups for `--asn-expand` (default 4096) |
| `--buckets` | cloud bucket permutation enumeration (S3/GCS/Azure) |
| `--bucket-keywords` | extra comma-separated bucket name keywords |
| `--nvd` | resolve CPEs to CVEs via NVD (slow, rate-limited, cached) |
| `--diff` | diff against previous run snapshot |
| `--nuclei` | run nuclei templated vuln scan on live hosts (needs nuclei) |
| `--nuclei-severity` | min nuclei severity, e.g. `medium,high,critical` |
| `--no-pd` | force pure-Python; ignore ProjectDiscovery binaries |
| `--screenshots` | capture live-host screenshots (needs playwright) |
| `--resolvers` | comma-separated DNS servers (default 1.1.1.1,8.8.8.8,9.9.9.9,8.8.4.4) |
| `-c, --concurrency` | max concurrent operations (default 50) |
| `--no-progress` | disable the rich progress bar |
| `-o, --out` | output basename (default `lrecon`) |

---

## Output

Per run, `<out>.*`:

- **`<out>.md`** — the deliverable: summary, source-contribution table, change-since-last-run,
  breach/GitHub/bucket exposure, nuclei findings, email posture, Cloudflare origin exposure, subdomain-takeover
  leads, favicon pivots, full attack-surface table, CVE hits.
- **`<out>.html`** — self-contained styled HTML report for client sharing.
- **`<out>.json`** — hosts plus every findings block (cf, email, github, buckets, breach, asn,
  favicon_pivots, diff, per_source).
- **`<out>.live.txt`** — deduplicated live URLs for tool handoff.
- **`<out>_shots/`** — live-host screenshots (with `--screenshots`).

Run snapshots are cached under `~/.local/share/lrecon/` to power `--diff`.

---

## Notable features

**Per-source attribution.** Every run prints and reports how many in-scope hosts
each passive source returned, so you can see whether crt.sh (frequently down) is
actually contributing or whether the other CT sources are carrying the run.

**Unique-IP enrichment.** Enrichment runs once per distinct IP, not per subdomain.
On CDN-fronted targets where hundreds of hosts share a few IPs this cuts API calls
and wall time dramatically, and respects Shodan's ~1 req/s limit.

**Wildcard filtering.** Detects wildcard DNS by resolving a random label first,
then drops phantom subdomains so they never reach your report.

**Subdomain-takeover leads (T1584.001).** Dangling CNAMEs to unclaimed
S3/GitHub Pages/Heroku/Azure/etc. are flagged, distinguishing a matched
unclaimed-service signature (high confidence) from a takeover-prone CNAME (lead).

**Cloudflare origin discovery.** When Cloudflare fronts a host, lrecon collects
origin-IP candidates passively — unproxied in-scope subdomains, SPF `ip4:`/`ip6:`
literals, MX host IPs, and a Shodan `ssl.cert.subject.CN` search — then (active
mode only) confirms a candidate by sending it a spoofed `Host` header. A confirmed
origin is an **origin IP disclosure / WAF-bypass** finding; the report includes a
baseline CVSS vector and remediation (restrict origin firewall to Cloudflare
ranges / Authenticated Origin Pulls / cloudflared tunnel).

---

## ROE tiers

| Mode | Resolution | HTTP probe | Port scan | CF confirm |
|---|---|---|---|---|
| `--passive-only` | no | no | no | no |
| default | yes | yes | no | yes |
| `--active-ports` | yes | yes | yes | yes |

The only steps that touch target-owned infrastructure directly are the HTTP probe,
the optional TCP scan, and the Cloudflare origin **confirmation** request. All
subdomain/enrichment/candidate collection is passive.

---

## Legal / ROE

This tool is for authorized security testing only. Running any active mode against
infrastructure you do not own or lack written authorization to test may be illegal.
You are responsible for staying within your signed scope and rules of engagement.
ATT&CK mapping: TA0043 Reconnaissance; passive ~T1596/T1593; active ~T1595/T1590;
subdomain takeover ~T1584.001.

---

## Development

```fish
pip install -e '.[dev]'   # pytest + pytest-asyncio
pytest -q                 # run the unit suite
```

Tests cover the pure-logic paths and the ProjectDiscovery backend parsers (via
monkeypatched output) — no network required. CI runs import + `--check-backends`
+ `pytest` across Python 3.10-3.12 on every push.

## Roadmap

- On-disk enrichment cache with TTL (currently only run-snapshot cache for diffing)
- ProjectDiscovery `httpx`/`naabu`/`nuclei` as optional native backends
- DeHashed integration for full credential exposure (paid)
- Wappalyzer-grade tech fingerprinting
