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

## Optional backends (ProjectDiscovery + psql)

lrecon uses external binaries as **optional native accelerators** when they're on
PATH, falling back to pure-Python/HTTP otherwise (nothing is required):

| Tool | Accelerates | Fallback |
|---|---|---|
| `subfinder` | passive subdomain enum | keyless CT/passive-DNS sources |
| `dnsx` | mass A/AAAA/CNAME resolution | dnspython per-host |
| `httpx` | HTTP probe + tech fingerprint + favicon | built-in probe |
| `naabu` | port scan (`--active-ports`) | async TCP connect scan |
| `nuclei` | templated vuln scan (`--nuclei`) | — (no fallback; skipped if absent) |
| `psql` | crt.sh subdomain enum via its **direct Postgres replica**, bypassing the flaky HTTP/JSON frontend entirely | hardened HTTP/JSON (retry + backoff) |

`psql` isn't a ProjectDiscovery tool, but gets the same optional-accelerator
treatment: `crt.sh -h crt.sh -p 5432 -U guest -d certwatch` is a public, read-only,
keyless replica documented by crt.sh itself. If `psql` is on PATH, lrecon queries it
directly for each domain; if it's absent or returns nothing, it falls back to the
HTTP JSON endpoint (4 attempts, exponential backoff).

Install them (Go, plus `psql` from your package manager):

```fish
go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,dnsx/cmd/dnsx,httpx/cmd/httpx,naabu/v2/cmd/naabu,nuclei/v3/cmd/nuclei}@latest
```

Startup logs which backends are active. `--no-pd` forces pure-Python/HTTP for
everything, including `psql` (reproducible runs / debugging / sandboxed
environments with no external binaries). Validate the integration before an
engagement:

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
| DNS records | apex A/AAAA/MX/NS/SOA snapshot + mail infrastructure ID (provider/ASN/org per MX host) | DNS only |
| WHOIS/RDAP | domain registration data: registrar, created/expires, nameservers, status (always on) | none (third-party registry) |
| People OSINT | company email enumeration: Hunter.io, GitHub commit history, RocketReach (opt-in, keyed) | none (API) |
| Search-engine dorking | admin/login/config/backup/`.git`/API-doc exposure via Google Custom Search (opt-in, keyed — see [Search-engine dorking](#search-engine-dorking)) | none (API) |
| VirusTotal domain intel | historical IP/hosting resolutions, WHOIS mirror, reputation (opt-in, keyed — see [Domain intelligence & IP/hosting history](#domain-intelligence--iphosting-history-virustotal)) | none (API) |
| Email verify | SMTP RCPT-TO probe of discovered emails (opt-in, `--verify-emails`) | yes, mail infra |
| CVE | NVD CPE->CVE resolution (opt-in, cached) | none (API) |
| Diff | change vs previous run snapshot | none |

Sources are keyless except **Shodan** and **subfinder**. Shodan/InternetDB only
hold data for IPs they have already indexed, so they are often empty — that is
expected. IPinfo fills ASN/org/rDNS regardless of whether a token is
configured — keyless requests just hit a lower, unauthenticated rate limit.

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
| IPinfo | ASN / org / reverse-DNS / geo | `--ipinfo-key` | `IPINFO_TOKEN` | 50k/mo keyed; keyless also works at a lower, unauthenticated rate limit |
| GitHub | code dorking for leaked secrets/hostnames; also company email harvest (see [People OSINT](#people-osint-user-enumeration)) | — | `GITHUB_TOKEN` | free |
| HIBP | breach-by-domain (keyless list endpoint) | — | `HIBP_API_KEY` | keyless list |
| Hunter.io | company email enumeration + naming-pattern detection | `--hunter-key` | `HUNTER_API_KEY` | limited |
| RocketReach | company people search (name/title only — see below) | `--rocketreach-key` | `ROCKETREACH_API_KEY` | limited |
| Google Custom Search | `--dork` entry-point search (admin/login/config/backup exposure) | `--google-cse-key` / `--google-cse-cx` | `GOOGLE_CSE_KEY` / `GOOGLE_CSE_CX` | 100 queries/day |
| VirusTotal | `--vt` domain intelligence — historical IP/hosting resolutions, WHOIS mirror, reputation | `--vt-key` | `VT_API_KEY` | 500/day, 4 req/min |

```fish
# persistent (fish universal vars — visible inside the venv)
set -Ux SHODAN_API_KEY "..."
set -Ux IPINFO_TOKEN   "..."

# or config file
mkdir -p ~/.config/lrecon
echo '{"shodan_api_key":"...","ipinfo_token":"...","hunter_api_key":"...","rocketreach_api_key":"...","google_cse_key":"...","google_cse_cx":"...","vt_api_key":"..."}' > ~/.config/lrecon/config.json

# or interactive (stays out of shell history)
lrecon example.com --ask-keys
```

Without a Shodan key, lrecon falls back to keyless **InternetDB** for ports/CVEs.

**On-boot verification.** Every configured key gets one cheap, non-quota-consuming
check (an account-info endpoint, not the actual feature endpoint) right at startup,
so a bad/expired key shows up immediately instead of silently degrading a phase
later in the run:

```
[+] Shodan API: Ready — query credits: 100
[!] IPinfo API: Invalid — falling back to keyless (lower rate limit, ASN/org/rDNS still enriched)
[+] GitHub API: Ready (as octocat)
[!] Hunter.io API: Invalid — company email OSINT via Hunter disabled
```

An invalid key is nulled out for the rest of the run (same automatic fallback
behavior as always relied on for Shodan) — you don't need to re-run without it.
HIBP gets a neutral note instead of a check: its breach-by-domain lookup uses
HIBP's keyless endpoint, so a configured `hibp_api_key` isn't sent anywhere yet.

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

# large client domain lists from a file instead of the command line
# (one domain per line; blank lines and #-comments skipped; merged with
# any positional domains, deduped)
lrecon -iL client_domains.txt -o client

# everything OSINT/informational — buckets, dorking, VirusTotal, NVD CVEs,
# ASN expansion — each still skips on its own if its key/binary isn't
# configured. --active-ports/--verify-emails/--nuclei stay opt-in even
# here — all three send live traffic straight at the target's hosts.
lrecon client.com --all -o client_full_osint
```

### Handoff to nuclei / httpx / nmap

```fish
lrecon client.com -o client
nuclei -l client.live.txt -o client_nuclei.txt
httpx -l client.live.txt -tech-detect -title

# if a Cloudflare origin candidate was found, scan what CF was masking
nmap -iL client.origin_ips.txt -p- -oA client_origin_scan
nuclei -l client.origin_ips.txt -o client_origin_nuclei.txt
```

### Key flags

| Flag | Effect |
|---|---|
| `-iL, --domains-file` | read domains from a file, one per line, merged with positional domains |
| `--passive-only` | OSINT sources + host lookup only; no resolution/HTTP/portscan |
| `--all` | turn on every OSINT/informational check that's otherwise opt-in only due to quota/speed/binary availability — `--buckets --dork --vt --nvd --asn-expand`. Does **not** enable `--active-ports`/`--verify-emails`/`--nuclei` (those send live traffic at the target and stay explicit — see below) |
| `--active-ports` | async TCP connect scan of common ports (aggressive; ROE-gated) |
| `--ports a,b,c` | custom port set for `--active-ports` |
| `--no-cf-origin` | disable Cloudflare origin-IP discovery |
| `--asn-expand` | expand scope via ASN->netblocks + reverse-DNS sweep (aggressive) |
| `--asn-cap N` | max PTR lookups for `--asn-expand` (default 4096) |
| `--buckets` | cloud bucket permutation enumeration (S3/GCS/Azure) |
| `--bucket-keywords` | extra comma-separated bucket name keywords |
| `--nvd` | resolve CPEs to CVEs via NVD (slow, rate-limited, cached) |
| `--company-name` | company name override for name-based people-enum sources (default: domain label) |
| `--verify-emails` | SMTP RCPT-TO probe of discovered company emails (active, ROE-gated) |
| `--dork` | search-engine dork for exposed admin/login/config/backup/`.git` paths (needs `--google-cse-key` + `--google-cse-cx`) |
| `--google-cse-key` | Google Custom Search API key for `--dork` (else env/config) |
| `--google-cse-cx` | Google Custom Search Engine ID for `--dork` (else env/config) |
| `--vt` | VirusTotal domain intelligence: IP/hosting history, WHOIS mirror, reputation (needs `--vt-key`) |
| `--vt-key` | VirusTotal API key for `--vt` (else env/config) |
| `--diff` | diff against previous run snapshot |
| `--nuclei` | run nuclei templated vuln scan on live hosts (needs nuclei; active, ROE-gated — not enabled by `--all`) |
| `--nuclei-severity` | min nuclei severity, e.g. `medium,high,critical` |
| `--no-pd` | force pure-Python/HTTP; ignore ProjectDiscovery binaries and the psql-based crt.sh accelerator |
| `--screenshots` | capture live-host screenshots (needs playwright) |
| `--resolvers` | comma-separated DNS servers (default 1.1.1.1,8.8.8.8,9.9.9.9,8.8.4.4) |
| `-c, --concurrency` | max concurrent operations (default 50) |
| `--no-progress` | disable the rich progress bar |
| `-o, --out` | output basename (default `lrecon`) |

---

## Output

Per run, `<out>.*`:

- **`<out>.md`** — the deliverable: summary, source-contribution table, change-since-last-run,
  breach/GitHub/bucket exposure, nuclei findings, email posture, domain registration (WHOIS/RDAP),
  VirusTotal domain intelligence & IP/hosting history, DNS records, mail infrastructure,
  search-engine dork hits, Cloudflare origin exposure, subdomain-takeover leads, favicon pivots,
  full attack-surface table, CVE hits.
- **`<out>.html`** — self-contained styled HTML report for client sharing. Same section
  coverage as the Markdown report, each in a collapsible panel (expand/collapse-all
  toggle, light/dark/print styles) with a client-side "Export CSV" button per table —
  no server, no external JS/CSS, works fully offline from the file.
- **`<out>.json`** — hosts plus every findings block (cf, email, github, buckets, breach, asn,
  favicon_pivots, diff, per_source, entry_points, whois, dorks, dns, mail_infra, vt, people).
- **`<out>.live.txt`** — deduplicated live URLs for tool handoff.
- **`<out>.origin_ips.txt`** — Cloudflare-origin-candidate IPs (confirmed + unconfirmed),
  one per line, if any were found — direct handoff to `nmap -iL` / `nuclei -l` to scan what
  Cloudflare was masking. Not written if no candidates were found.
- **`<out>.targets.csv`** — flat subdomain/IP/ASN/org list for client scope confirmation.
- **`<out>.users.csv`** — enumerated company emails, if any hunter/rocketreach/github
  key is configured (see [People OSINT](#people-osint-user-enumeration)).
- **`<out>_shots/`** — live-host screenshots (with `--screenshots`).

Run snapshots are cached under `~/.local/share/lrecon/` to power `--diff`.

---

## Notable features

**Per-source attribution.** Every run prints and reports how many in-scope hosts
each passive source returned, so you can see whether crt.sh (frequently down) is
actually contributing or whether the other CT sources are carrying the run.
crt.sh itself prefers a direct Postgres query over its flaky HTTP frontend when
`psql` is available — see [Optional backends](#optional-backends-projectdiscovery--psql).

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
mode only) confirms a candidate by sending it a spoofed `Host` header. Every
candidate IP is enriched with ASN/org (via IPinfo, if configured) so you can
immediately see whether a leaked origin sits on the client's own infrastructure
or a third party's. A confirmed origin is an **origin IP disclosure / WAF-bypass**
finding; the report includes a baseline CVSS vector and remediation (restrict
origin firewall to Cloudflare ranges / Authenticated Origin Pulls / cloudflared
tunnel).

**Tech-stack confirmation for CVE hits.** Shodan/InternetDB CVE data comes
from a periodic internet-wide scan that can be weeks old. Where a live
tech-detect probe is available (ProjectDiscovery `httpx -td`, Wappalyzer-based —
see [Optional backends](#optional-backends-projectdiscovery--psql)), lrecon
cross-references each host's reported CPEs against what's actually being
served right now and marks the CVE hit **tech-confirmed** (still corroborated)
or **unconfirmed** (no live match — banner may be stale, or the software's
been patched/replaced) in both the CVE hits table and the entry-points
summary. Triage tech-confirmed hosts first to cut down manual validation
work. Without the `httpx` binary installed, lrecon falls back to reading
just the `Server`/`X-Powered-By` headers — no Wappalyzer fingerprinting — so
confirmation stays unavailable (`None`, shown as `—`) until it's installed;
run `lrecon --check-backends` to confirm it's on PATH.

**Non-web port highlighting.** The HTTP probe/tech-detect pipeline only ever
touches general-purpose web/app-proxy ports (80, 443, 8080, 8443, etc.).
Anything else open — SSH, RDP, SMB, VNC, WinRM, databases (MySQL, Postgres,
Redis, MongoDB, MSSQL), Elasticsearch, and so on — never gets probed, so it's
highlighted in the Attack Surface table (bold in Markdown, an amber badge in
HTML) and surfaced as its own **entry-points** finding (`T1046`, Network
Service Discovery) naming the service where recognized. Direct RCE/lateral-
movement-prone services (RDP, SMB, VNC, WinRM, Telnet) rank **high**;
databases and auth-adjacent services (FTP, LDAP, MSSQL/MySQL/Postgres,
RPC/NetBIOS) rank **medium**; commonly-intentional exposures (SSH, mail,
DNS) rank **low**. An unrecognized open port still gets flagged, at a
conservative medium, even without a friendly name.

---

## People OSINT (user enumeration)

Builds a red-team phishing/password-spray candidate list — **company-affiliated
data only**, never personal accounts or personal contact info. Runs automatically
whenever a Hunter.io, RocketReach, or GitHub key is configured (same "presence of
a key = opt-in" convention as the rest of lrecon's keyed enrichment); output goes
to `<out>.users.csv` and the `people` block in the JSON.

| Source | What it gives you | Notes |
|---|---|---|
| **Hunter.io** | known company emails + the detected naming pattern (e.g. `{first}.{last}`) | official domain-search API |
| **GitHub** | company emails leaked in public commit/code history | reuses your `GITHUB_TOKEN`; shares the code-search rate limit with `--github` dorking |
| **RocketReach** | name + title (no email) via their official search API | see caveat below |

**No LinkedIn scraping.** lrecon does not scrape LinkedIn (or RocketReach's site)
directly — that would mean defeating anti-automation measures and violating
those platforms' terms of service, a materially different risk than the
official, documented APIs above. RocketReach support is via their official API
only, and deliberately skips their credit-consuming "reveal" endpoint — you get
name/title/LinkedIn-URL, not a spent-credit email. When Hunter has detected a
naming pattern, lrecon applies it to RocketReach names to produce a **candidate**
company email — always marked `generated=yes` in the CSV, never claimed as
observed.

**`--company-name`** overrides the company-name guess (derived from the domain
label by default) for sources that search by name rather than domain.

**`--verify-emails`** (opt-in, separate from discovery) does an SMTP `RCPT TO`
probe of every discovered email against the domain's MX — an **active**
technique that directly touches the target's live mail infrastructure; many
orgs alert on it. It detects catch-all domains first (a deliberately-nonexistent
address accepted too) and marks every result `catch-all` rather than reporting
false `valid` positives. Many providers (Microsoft 365, Google Workspace, or
anything blocking port 25 from cloud/datacenter source IPs) will make this come
back `unknown` for the whole domain — expected, not a bug.

---

## Search-engine dorking

Finds exposed admin/login panels, config/env files, directory listings, and
`.git`/backup leaks indexed by Google against each in-scope domain — the
`site:` dork techniques security testers run by hand, automated across
seven curated categories per domain (admin/login panels, config/env
exposure, directory listing, backup/database files, exposed `.git`,
API/swagger docs, debug/error pages). Findings feed the entry-points
summary tagged **T1593.002** (Search Open Websites/Domains: Search Engines).

Opt-in via **`--dork`**, and requires a **Google Custom Search JSON API**
key + Custom Search Engine ID (`--google-cse-key`/`--google-cse-cx`, or
`GOOGLE_CSE_KEY`/`GOOGLE_CSE_CX`, or config file). It's an explicit flag
even when a key is configured — unlike the "presence of a key = opt-in"
convention used for the People OSINT sources — because the free tier is
only **100 queries/day total** and each domain burns ~7 of them; auto-running
it could silently exhaust the day's quota on a run where you didn't need it.

**No raw search-engine scraping.** Like the [People OSINT](#people-osint-user-enumeration)
LinkedIn decision above, lrecon does not scrape Google or DuckDuckGo HTML
result pages directly — that means defeating anti-automation measures and
violating those platforms' terms of service. Dorking uses Google's official,
keyed, documented Custom Search API only. There is no DuckDuckGo fallback.

A hit is a search-engine-indexed page matching a dork pattern, not a
confirmed live exposure — verify each is actually reachable before
reporting it, since a Google result can be stale.

## Domain registration (WHOIS/RDAP)

Every run looks up each domain's registration data — registrar, creation/
expiration dates, nameservers, and status codes — via **RDAP** (the
structured-JSON successor to WHOIS), queried keylessly over HTTPS through
`rdap.org`'s public bootstrap redirector to the authoritative registry. No
system `whois` binary is used or required. This always runs, including
under `--passive-only`, since it only touches a third-party registry, never
the target's own infrastructure. A domain expiring within 30 days is flagged
in the run log as worth raising with the client.

Every in-scope domain gets a row in the report's "Domain registration
(WHOIS/RDAP)" section, even if the lookup itself came back empty
(unsupported TLD, typo, transient failure) — check the run log for a
`whois/rdap` line when a domain shows all `—`.

**Registrant disclosure & privacy protection.** The registry-level RDAP
response (what `rdap.org` returns directly) omits registrant data entirely
for most gTLDs post-GDPR — that's normal, not an error. lrecon follows the
registrar's own RDAP referral link (present in the registry response) one
extra hop to get the fuller picture, then reports one of three states per
domain:

- **Privacy-protected** — a redaction marker or a privacy-service name
  (WhoisGuard, Withheld for Privacy, Domains By Proxy, etc.) was found; the
  provider name is shown.
- **Registrant name/org shown** — real registrant data was disclosed (no
  redaction marker, no privacy-service pattern).
- **Unknown** — no registrant entity was returned by either the registry or
  the registrar referral (common for some ccTLDs); this is *not* the same
  as "confirmed not privacy-protected," and the report says so explicitly.

## Domain intelligence & IP/hosting history (VirusTotal)

RDAP/WHOIS covers registration data, but not *hosting* history — which IPs
a domain has actually pointed to over time, and when. That's the piece a
paid tool like DomainTools normally provides; **`--vt`** gets you the
closest free equivalent via VirusTotal's official public API v3:

- **Historical IP resolutions** (hosting history) — every domain→IP passive-DNS
  resolution VT has observed, newest first, each with a first-seen date.
- **WHOIS mirror, cached DNS records, reputation/detection stats** — VT's own
  domain snapshot, useful as a cross-check against the RDAP data above.

Requires **`--vt-key`** (or `VT_API_KEY`/config). It's an explicit flag even
with a key configured — unlike the "presence of a key = auto-run" convention
used for the People OSINT sources — because the free tier is rate-limited to
**4 requests/minute** (500/day) and each domain costs two calls, so
auto-running it would add real wall-clock time (up to ~30s/domain) to a run
where you didn't ask for it. It's passive (only queries VT's own API, never
the target directly), so it still runs under `--passive-only`.

A high malicious/suspicious vote count on a client-owned domain in the report
is usually a false positive from a prior compromise or shared/CDN
infrastructure another tenant polluted — verify before reporting it as a
finding.

## DNS records & mail infrastructure

Every run (outside `--passive-only`) captures an apex-level DNS snapshot per
domain — `A`/`AAAA`/`MX`/`NS`/`SOA` — reported in its own **DNS records**
section, distinct from the per-subdomain resolution table and from the
SPF/DMARC/DKIM-only view in the email security section. It's gated the same
way as the rest of Phase 2 resolution (a DNS query against the domain's own
authoritative nameservers, not a third-party API), so it doesn't run under
`--passive-only`, unlike the keyless RDAP/WHOIS lookup above.

Each MX host found is then resolved to an IP and enriched (ASN/org/country,
reusing the same IPinfo enrichment as host IPs) and labeled against a list of
well-known managed-email providers — Google Workspace, Microsoft 365,
Proofpoint, Mimecast, Barracuda, Cisco Secure Email, Zoho, Amazon SES/WorkMail,
Yandex — so the **Mail infrastructure** section reads "Google Workspace"
rather than an opaque MX hostname. A domain whose MX doesn't match any known
provider is flagged in the run log as possibly self-hosted — worth a closer
look (SMTP banner grab, open relay, vulnerable MTA version) if in scope.

---

## ROE tiers

| Mode | Resolution | HTTP probe | Port scan | CF confirm |
|---|---|---|---|---|
| `--passive-only` | no | no | no | no |
| default | yes | yes | no | yes |
| `--active-ports` | yes | yes | yes | yes |

The steps that touch target-owned infrastructure directly are the HTTP probe,
the optional TCP scan, the Cloudflare origin **confirmation** request, the
optional nuclei templated scan (`--nuclei` — sends live requests, including
exploit/auth-bypass probes, to live hosts), and (if `--verify-emails` is set)
the SMTP `RCPT TO` probe of the target's mail servers. All subdomain/
enrichment/candidate collection — including all people-OSINT discovery,
before `--verify-emails` — is passive.

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
