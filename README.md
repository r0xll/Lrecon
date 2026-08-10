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
  enrich.py      ipinfo/shodan/nvd/favicon  intel.py     cloudflare/email/github/buckets/breach/auth-surface
  active.py      http probe + tcp scan      backends.py  ProjectDiscovery wiring
  state.py       cache + diff               report.py    markdown / html / live / screenshots
  people.py      company email/people OSINT dorking.py   dork search (CSE/Brave/Vertex)
  llm.py         provider-neutral LLM layer news.py      factual company-intel (SEC EDGAR)
  dossier.py     dossier assembly + writers
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
| 1. Passive enum | crt.sh, Cert Spotter, Anubis, Wayback CDX, OTX (keyed), Shodan DNS, subfinder | none |
| 2. Resolution | shared fast resolver, A/AAAA/CNAME concurrent, wildcard filtering | DNS only |
| 3. Enrichment | per **unique IP**: IPinfo (ASN/org/rDNS) + Shodan host / InternetDB (ports/CVE) | none (API) |
| 4. Active | HTTP probe, favicon hash, takeover checks, optional TCP scan | yes |
| CF origin | Cloudflare detection + origin-IP candidates (+ optional confirm) | confirm step only |
| Expansion | ASN->netblock (RIPEstat) + reverse-DNS sweep, rDNS wire-back | DNS only |
| Intel | email posture (SPF/DKIM/DMARC), GitHub dorking, cloud buckets, breach, favicon pivot (Shodan) | none / provider |
| DNS records | apex A/AAAA/MX/NS/SOA snapshot + mail infrastructure ID (provider/ASN/org per MX host) | DNS only |
| WHOIS/RDAP | domain registration data: registrar, created/expires, nameservers, status; falls back to classic WHOIS (port 43), then to `--vt`'s cached WHOIS text, for TLDs/environments where RDAP has nothing (always on) | none (third-party registry) |
| Auth surface | passive OIDC/SSO discovery — reads each live host's `/.well-known/openid-configuration` and fingerprints the identity provider (Okta, Entra/Azure AD, Auth0, Ping, ADFS, Google, Keycloak). Discovery only: no login/credential probing (not run under `--passive-only`) | yes (one GET/host) |
| People OSINT | company email enumeration: website scrape (keyless), Hunter.io, GitHub commit history, RocketReach | website scrape only |
| Search-engine dorking | admin/login/config/backup/`.git`/API-doc exposure via Google Custom Search (opt-in, keyed — see [Search-engine dorking](#search-engine-dorking)) | none (API) |
| VirusTotal domain intel | historical IP/hosting resolutions enriched with org/country + origin candidates, WHOIS mirror, reputation (opt-in, keyed — see [Domain intelligence & IP/hosting history](#domain-intelligence--iphosting-history-virustotal)) | none (API) |
| Email verify | SMTP RCPT-TO probe of discovered emails (opt-in, `--verify-emails`) | yes, mail infra |
| CVE | NVD CPE->CVE resolution (opt-in, cached) | none (API) |
| Diff | change vs previous run snapshot | none |

Sources are keyless except **Shodan**, **subfinder** and **OTX**. Shodan/InternetDB only
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

`pip install -e .` is everything you need — including live TLS certificate
inspection. Note the **quotes** on the extras line above: `[` and `]` are glob
characters in fish and zsh, so an unquoted `pip install -e .[screenshots]` fails
with a wildcard error rather than installing anything.

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
| Search-engine dorking | `--dork` entry-point search (admin/login/config/backup exposure) via Google CSE / Brave Search / Vertex AI Search (`--dork-provider`) | `--google-cse-key`+`--google-cse-cx` / `--brave-key` / `--vertex-*` | `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX` / `BRAVE_SEARCH_API_KEY` / `VERTEX_*` | Google CSE 100/day, Brave 2k/mo |
| VirusTotal | `--vt` domain intelligence — historical IP/hosting resolutions, WHOIS mirror, reputation | `--vt-key` | `VT_API_KEY` | 500/day, 4 req/min |
| AlienVault OTX | passive-DNS subdomain enum. Anonymous access is refused (429), so this source contributes nothing without a key | `--otx-key` | `OTX_API_KEY` | free |

Every key is validated at startup against an endpoint that costs no quota — except **Brave**, which has no free account endpoint, so validating the key *is* spending a search. That check therefore runs only when `--dork` is requested; an ordinary scan never touches the Brave quota.

```fish
# persistent (fish universal vars — visible inside the venv)
set -Ux SHODAN_API_KEY "..."
set -Ux IPINFO_TOKEN   "..."

# or config file
mkdir -p ~/.config/lrecon
echo '{"shodan_api_key":"...","ipinfo_token":"...","hunter_api_key":"...","rocketreach_api_key":"...","google_cse_key":"...","google_cse_cx":"...","brave_search_key":"...","vertex":{"access_token":"...","project":"...","engine":"..."},"vt_api_key":"..."}' > ~/.config/lrecon/config.json

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
| `--dork` | search-engine dork for exposed admin/login/config/backup/`.git` paths (backend chosen by `--dork-provider`) |
| `--dork-provider` | dork backend: `auto` (default), `google`, `brave`, or `vertex` — see [Search-engine dorking](#search-engine-dorking) |
| `--google-cse-key` / `--google-cse-cx` | Google Custom Search API key + Engine ID (else env/config). Google CSE is closed to new customers |
| `--brave-key` | Brave Search API key for `--dork` (else `BRAVE_SEARCH_API_KEY`/config) |
| `--vertex-access-token` / `--vertex-project` / `--vertex-engine` / `--vertex-datastore` / `--vertex-location` | Vertex AI Search creds for `--dork` (else env/config) |
| `--vt` | VirusTotal domain intelligence: IP/hosting history, WHOIS mirror, reputation (needs `--vt-key`) |
| `--vt-key` | VirusTotal API key for `--vt` (else env/config) |
| `--diff` | diff against previous run snapshot |
| `--nuclei` | run nuclei templated vuln scan on live hosts (needs nuclei; active, ROE-gated — not enabled by `--all`). Streams nuclei's own periodic scan-status lines live so a long scan isn't a silent wait |
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
  full attack-surface table (with per-host country), CVE hits.
- **`<out>.html`** — self-contained styled HTML report for client sharing. Same section
  coverage as the Markdown report, each in a collapsible panel (expand/collapse-all
  toggle, light/dark/print styles) with a client-side "Export CSV" button per table —
  no server, no external JS/CSS, works fully offline from the file.

  The **attack-surface table is filterable in place**, which is what makes it usable
  on a scope with hundreds of rows. Each column has a box under its header:

  | Type | Effect |
  |---|---|
  | `nginx` in **Tech** | keep only rows whose Tech contains `nginx` |
  | `20` in **Open Ports** | anything containing 20 — port 20, 2070, 8020 |
  | `443,8080` in **Open Ports** | either one — comma-separated values are ORed |
  | `!403` in **HTTP** | *remove* the 403s — a leading `!` negates |
  | `!403,404` in **HTTP** | remove both |
  | `!—` in **CVEs** | only hosts that have a CVE (empty cells render as `—`) |

  Matching is **case-insensitive substring in every column**, numbers included:
  filtering is exploratory, and you rarely know the exact port up front — which
  is why you are filtering. Columns combine with AND. The syntax is spelled out
  in a box above the filter row, and a `showing N of M` counter sits beside it so
  a filtered view is never mistaken for a short one. **Export CSV writes exactly
  the rows on screen** — filter, then export, and the file matches what you were
  looking at.

  The **TLS certificates** table has the same filter row; `!—` under Flags leaves
  only the certificates with something wrong with them.
- **`<out>.json`** — hosts plus every findings block (cf, email, github, buckets, breach, asn,
  favicon_pivots, diff, per_source, entry_points, whois, dorks, dns, mail_infra, vt, people,
  auth_surface).
- **`<out>.live.txt`** — deduplicated live URLs for tool handoff.
- **`<out>.origin_ips.txt`** — Cloudflare-origin-candidate IPs (confirmed + unconfirmed),
  one per line, if any were found — direct handoff to `nmap -iL` / `nuclei -l` to scan what
  Cloudflare was masking. Not written if no candidates were found.
- **`<out>.targets.csv`** — flat target list for client scope confirmation: one
  row per subdomain/IP pair (a multi-IP host repeats across several rows, one
  IP per row), each with its own org — no comma-joined multi-value cells.
- **`<out>.users.csv`** — enumerated company emails, if any hunter/rocketreach/github
  key is configured (see [People OSINT](#people-osint-user-enumeration)).
- **`<out>.dossier.json` / `<out>.dossier.md`** — the structured target dossier, with the
  `dossier` / `full-report` subcommands (see [AI-assisted dossier engine](#ai-assisted-dossier-engine-llm-synthesis)).
- **`<out>_shots/`** — live-host screenshots (with `--screenshots`).

Run snapshots are cached under `~/.local/share/lrecon/` to power `--diff`.

---

## Notable features

**Per-source attribution.** Every run prints and reports how many in-scope hosts
each passive source returned, so you can see whether crt.sh (frequently down) is
actually contributing or whether the other CT sources are carrying the run.
crt.sh itself prefers a direct Postgres query over its flaky HTTP frontend when
`psql` is available — see [Optional backends](#optional-backends-projectdiscovery--psql).

**crt.sh resilience.** crt.sh is the single flakiest source in the pipeline, so it
gets three layers of defense:

- The **direct-Postgres tier is time-boxed** (8s connect / 12s total). Raw TCP to
  port 5432 is blocked outright in some sandboxed environments — Claude Code's own
  containers included, same restriction that affects classic WHOIS/port 43 — and a
  blocked connect there *hangs* rather than refusing. Without a short budget that
  first tier stalls every domain before the HTTP tier ever runs, which looks
  exactly like "crt.sh is broken." Use `--no-pd` to skip the tier entirely.
- The **HTTP tier alternates two query forms** across retries (`?q=%.domain` and
  `?identity=%.domain`). Both cover the same pattern but take different paths
  through crt.sh's backend, and in practice one returns data while the other is
  502-ing. Retries are status-aware (429/5xx retried, other 4xx fail fast), and a
  `200` carrying a truncated/non-JSON body is treated as a failure to retry, not
  as an empty result.
- **Failures are legible**: the per-attempt statuses are logged, so an empty
  crt.sh result tells you *why* instead of vanishing silently. Cert Spotter, OTX,
  Anubis, Wayback, and Shodan DNS continue to cover the run regardless.

### When a source contributes 0

The `by source:` line reports what each source found, and `0` used to mean two
very different things — "this domain has no hosts here" and "this source is
blocked". Sources that fail now say so on their own line, because only the first
of those is a fact about the target:

| Source | Status |
|---|---|
| **Wayback CDX** | working, and now **retried**. The URL was `http://` and `web.archive.org` 301s to HTTPS, which the shared enum client doesn't follow — so it returned nothing on *every* target. It also 429s routinely under load, which used to cost the source for the whole run; there are now 4 attempts with backoff, honouring `Retry-After`. |
| **Anubis** | working. `jldc.me` 301s to `jonlu.ca`, which blocks automated clients — but that was never the canonical host. [Anubis-DB](https://github.com/jonluca/Anubis-DB) serves from **`anubisdb.com`**, and lrecon now queries that. |
| **OTX** | **needs an API key.** Anonymous callers get `429 — "Anonymous access to this endpoint is limited. Please authenticate."` Set `--otx-key`/`OTX_API_KEY` and it works again; without one, the failure line says so rather than looking like a clean domain. |

A source that works for one domain in the scope is not reported as failed
because it 403'd on another.

**Persistent wayback 429s are usually your exit IP.** archive.org rate-limits shared and VPN ranges hard (TorGuard and similar), so a commercial VPN will 429 every attempt no matter how patiently lrecon backs off. Nothing to fix in the tool — run that source from a different egress if you need it.

Note that lrecon deliberately does **not** send `exclude=expired`. It shrinks the
result set (fewer planner timeouts) but measured against `example.com` it dropped
77 names to 20 — and expired certificates are exactly where forgotten
dev/staging hostnames live, which is the point of CT enumeration.

**Certificate-name scoping.** CT names are matched on the label boundary, not with
a bare suffix test: `%.example.com` legitimately returns names like
`m.testexample.com`, and a plain `endswith()` would pull that unrelated
third-party host into the engagement scope. Certificate `rfc822Name` subjects
(e.g. `someone@example.com`) are dropped too — they're not hosts to scan.

**Cloud storage exposure with object detail.** A public bucket is only actionable
if you know what's *in* it, so `--buckets` parses the listing response it already
fetched (no extra requests, no downloads) and reports:

- a **direct link** to each bucket and to **every object key**, per provider
  (S3 / GCS / Azure URL forms), so findings are one click from verification;
- **object count, total size, and a truncation flag** when the provider capped the
  listing;
- **sensitive-looking objects flagged and listed first** — credentials/config
  (`.env`, `.env.production`, `web.config`), database/source dumps (`.sql`,
  `db.sql.gz`, `.bak`), keys and secret stores (`.pem`, `id_rsa`, `.kdbx`,
  `.aws/credentials`), infra state (`.tfstate`, `.kubeconfig`), and archives.
  Variant suffix forms are matched deliberately (`config.yml.bak`,
  `settings.ini.old`), since those are the highest-value keys in practice, while
  static assets (images, CSS, fonts, video) are not flagged.

A public bucket holding sensitive-looking objects is promoted to a **critical**
entry point (from high) and the finding names the top offending keys, so the
entry-points table alone is enough to triage. lrecon lists but never downloads
object contents — fetch only what your ROE permits.

**Email security posture with the full records.** The report shows the **verbatim
SPF, DMARC, and DKIM records** (and which DKIM selector matched) rather than only a
grade, so a reviewer can audit the mechanism without re-querying DNS. Alongside the
raw text it reports a parsed breakdown:

- **SPF** — the `all` qualifier (`-`/`~`/`?`/`+`), `include:` targets, `ip4:`/`ip6:`
  literals, `redirect=`, and the **DNS-lookup count against RFC 7208's limit of
  10**. Exceeding it is a `permerror` that can make receivers ignore SPF entirely —
  a real, commonly-missed finding — and the deprecated `ptr` mechanism is flagged.
  The count **expands `include:`/`redirect=` targets**, because §4.6.4's budget
  covers every lookup a receiver makes during the whole evaluation; counting only
  the apex record would miss the usual cause of a real permerror (a few includes
  that each pull in several more lookups). Expansion stops as soon as the limit is
  passed, so a pathological record cannot fan out — an over-limit figure is
  reported as "at least" that many. If a lookup inside an include fails, the count
  is labelled incomplete rather than being presented as confirmed compliance.
- **DMARC** — `p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`, with issues
  raised for `pct<100` (partial enforcement), `sp=none` (subdomains unprotected
  despite an enforced `p=`), and a missing `rua=` (no aggregate reporting).
- **DKIM** — the matched selector and its record, or the explicit list of selectors
  probed so a "not found" reads as inconclusive rather than absent.
- **MTA-STS + TLS-RPT** — SPF/DKIM/DMARC authenticate the *message*; MTA-STS
  (RFC 8461) protects the *connection*, telling senders to require TLS with a
  valid certificate. Without it STARTTLS is strippable by an active network
  attacker and mail silently downgrades to plaintext. lrecon reads the
  `_mta-sts` and `_smtp._tls` records and fetches the policy file to report the
  actual `mode`. Plain absence is reported as a field, **not** raised as an
  issue — most domains publish no MTA-STS, and treating that as a finding would
  push nearly every domain to WARN and make the grade useless. A published but
  *broken* policy is a real defect and does raise one, in three distinguishable
  states: the policy file is **unreachable**, it is **served but invalid** (a 200
  with no usable `mode=` — a catch-all page or a malformed file, so the published
  record isn't enforceable), or it is valid but not enforcing (`mode=testing` /
  `mode=none`). The remedies differ, so the report doesn't collapse them.

**SPF include health.** Expanding `include:`/`redirect=` for the lookup budget
also reveals targets that yield no usable SPF record, which used to be skipped
silently. Each one gets a follow-up resolution, because three situations look
identical in a plain TXT lookup and mean very different things:

| State | Meaning |
|---|---|
| **does not exist** (NXDOMAIN) | permerror — and if that domain is registrable, whoever registers it can publish SPF authorising their own mail *for your domain* |
| **no SPF record** | permerror — the mechanism can never match, but nobody can hijack it |
| **unchecked** | DNS error — inconclusive, never reported as either of the above |

Each finding names the mechanism it came from — `include:` or `redirect=` — and
the report flags the target where it's listed, so a broken `redirect=` is never
reported as an include the record doesn't contain.

The NXDOMAIN case reports the **closest still-existing zone** as evidence and
stops short of asserting the domain is registrable — same discipline as the
takeover confidence levels, and for the same reason (deciding that needs a
public-suffix list).

**Detected email services.** Fingerprinted from records lrecon already fetches:

- **Senders** from SPF includes — M365, Google Workspace, SendGrid, Mailgun,
  Salesforce, Zendesk, Docusign, Atlassian and others. For an authorized
  assessment this is the pretext surface: a target that sends via Docusign gives
  a lure that fits their normal mail flow.
- **DMARC reporting platform** from `rua=`/`ruf=` — Red Sift OnDMARC, dmarcian,
  Valimail, Proofpoint, EasyDMARC and others. This is the "is anyone actually
  watching?" signal.
- **Inbound gateway** from MX — Proofpoint, Mimecast, Barracuda, Cisco.

Matching is anchored to a domain boundary, so a lookalike
(`rua=mailto:x@notredsift.cloud.evil.com`) cannot borrow a vendor's name. All of
it is **informational and never moves the grade** — using a DMARC platform is
good practice, not a finding.

**Phishing posture read-out.** The above is synthesised into one line per domain
answering the question an operator actually has — *if I send as this domain, or
from a lookalike, what happens?* For example:

> `p=reject` at full coverage — spoofing the exact domain should fail at
> receivers honouring DMARC; aggregate reporting to Red Sift OnDMARC, so
> lookalike and spoofed sending is likely to be detected and reviewed; inbound
> mail is filtered by Proofpoint, which may quarantine lookalike-domain mail on
> arrival.

It describes likelihood and never guarantees an outcome — no DNS record supports
"will be blocked", since receivers honour DMARC to varying degrees. The
structured inputs (`enforced`, `monitored_by`, `gateway`, `senders`) are kept
beside the sentence so the conclusion can be audited rather than taken on trust.

**DNS zone transfer (AXFR).** One query per authoritative nameserver, reusing
the NS list the DNS snapshot already collected. A server that answers hands over
every record in the zone at once — including internal-only names no amount of
brute-forcing would surface — so a successful transfer is a **critical** entry
point (T1590.002). The report keeps the three outcomes distinct per nameserver:
**allowed** (the finding, with the disclosed names), **refused** (correct
configuration), and **not conclusive** (we couldn't reach it). That last
distinction matters — reporting an unreachable nameserver as "transfers refused"
would be a false negative. AXFR is TCP/53, which some sandboxed environments
block outright, and a blocked attempt lands in the inconclusive bucket rather
than being mistaken for a pass.

**security.txt (RFC 9116).** Read from the live hosts already probed. Useful two
ways: it names the disclosure channel a report should actually go to, and its
`Policy`/`Canonical`/`Acknowledgments` URLs routinely point at hosts nothing else
surfaced. An `Expires` date in the past is flagged — per the RFC the contact
details should no longer be relied on. A catch-all route that returns the app's
index page for every path is not mistaken for a published file.

**Unique-IP enrichment.** Enrichment runs once per distinct IP, not per subdomain.
On CDN-fronted targets where hundreds of hosts share a few IPs this cuts API calls
and wall time dramatically, and respects Shodan's ~1 req/s limit.

**Wildcard filtering.** Detects wildcard DNS by resolving a random label first,
then drops phantom subdomains so they never reach your report.

**Subdomain-takeover leads (T1584.001).** Dangling CNAMEs to unclaimed
S3/GitHub Pages/Heroku/Azure/etc. are flagged with an explicit confidence, and
the report lists the strongest leads first:

| Confidence | Signal |
|---|---|
| **confirmed** | the target is NXDOMAIN *and* sits under a provider where re-registering that exact name is the service on offer (or, for GitHub Pages, the account is verifiably unregistered) |
| **likely** | the provider's unclaimed-service signature matched in the response body |
| **possible** | the target is broken but claimability is unverified — reported with the closest still-existing zone as evidence |

Confidence turns on **claimability, not brokenness**. NXDOMAIN proves the target
doesn't exist; it does not prove an attacker could create it. A broken CNAME to a
typo under a partner's domain is NXDOMAIN too, yet nobody outside that partner
can register the name — calling that confirmed would be a critical-severity false
positive.

To let you judge the rest, lrecon reports the **closest still-existing zone**,
read from the SOA that an NXDOMAIN answer already carries. That one fact
separates the two cases behind an identical rcode: a closest zone of `com` means
the domain itself is unregistered and can simply be bought (a serious takeover),
while `partner-company.com` means only a label is missing inside someone else's
live zone. Deciding that automatically would need a full public-suffix list, so
the fact is surfaced rather than guessed at.

The NXDOMAIN path is DNS-only and needs no HTTP response, so it covers the case
the signature checks structurally cannot: a dangling CNAME usually has *no* A
record, so the host never reaches the HTTP probe at all. An inconclusive lookup
(timeout/SERVFAIL) is never reported as a finding.

**How each provider is actually claimed.** "Dangling" and "claimable" are
different questions, and only the second one is a takeover:

| Class | Meaning | Examples |
|---|---|---|
| **self-serve** | the exact target name is re-registrable by anyone — the classic takeover | S3 buckets, `github.io` usernames, Heroku and Azure app names, `surge.sh`, `pantheonsite.io` |
| **account-bound** | the hostname is provider-assigned, but the *domain* pointed at it may be attachable to another account, subject to the provider's domain verification | `fastly.net` (`d.sni.global.fastly.net` is a shared endpoint every customer points at) |
| **not claimable** | the name carries a provider-generated component and can never be issued again | `*.elb.amazonaws.com` — `k8s-…-d961a91db8-1411441002.us-east-1.elb.amazonaws.com` |

Not-claimable targets are reported under **Stale DNS records** instead of as
takeover leads. The record should still be removed, but there is nothing to
claim, and filing it as a takeover sends someone chasing a name AWS will never
issue again.

**GitHub Pages gets a definitive answer.** `*.github.io` is wildcarded, so a dead
Pages target never returns NXDOMAIN and only the body signature fires — and
GitHub serves the same *Site not found* page whether the account is unregistered
or merely has no site published. One `api.github.com/users/<account>` lookup
separates them: a 404 means the username is free and registering it claims the
hostname (**confirmed**), while a 200 means nobody else can claim it and the
record is stale rather than dangerous. A rate-limited or failed lookup leaves the
finding untouched — a lookup that didn't happen is not evidence either way. Set
`GITHUB_TOKEN` for the authenticated rate limit. This reasoning is CNAME-specific;
a domain pointed at the Pages A records names no account, and lrecon's
CNAME-keyed takeover path never sees that shape.

**A CNAME into a takeover-prone provider is not itself a finding.** Every healthy
site on GitHub Pages, Fastly, Heroku or S3 has one. lrecon reports a lead only
when the provider's unclaimed-service signature matches, or the host errors
(403/404/410/503) with wording lrecon doesn't recognise. A 2xx serving ordinary
content produces nothing.

**Live TLS certificate inspection.** Every other certificate signal in lrecon is
second-hand — CT logs (crt.sh/certspotter) and Shodan's `ssl.cert.subject.CN`
search. Reading the certificate a host *actually serves* adds what those can't:

- **SAN mining** — in-scope names on the live cert become hosts tagged
  `tls-san`, including names that never reached a CT log. Wildcards are dropped
  (not resolvable hosts), and so is anything outside scope: a shared or CDN
  certificate routinely carries other tenants' domains, which are not the
  client's assets.
- **Non-web TLS ports** — certs are read from the open TLS ports lrecon already
  discovers (`8443`, `993`, `995`, `465`, `587`, `636`, …), not just `443`.
  Forgotten internal hostnames sit on mail and admin endpoints nobody submits
  to CT.
- **Origin confirmation** — see below.
- **Hygiene facts** — expired, not-yet-valid, self-signed, near-expiry, issuer.

Certificates are read **without verification**, for the same reason lrecon keeps
an unverified probe client: targets routinely serve self-signed, expired or
mismatched certs, and those are exactly the ones worth reporting. Reading a cert
is not trusting it, and nothing is sent beyond the handshake.

This works out of the box: `cryptography` is a base dependency, so a plain
`pip install -e .` gets you cert inspection. It used to sit behind a `[tls]`
extra, which meant the default install quietly produced reports missing this
whole section. The `[tls]` extra still exists and is empty, so older commands
keep working. If the cert pass ever reports that cryptography failed to import,
that is a broken install rather than a missing extra —
`pip install --force-reinstall cryptography`.

**Cloudflare origin discovery.** When Cloudflare fronts a host, lrecon collects
origin-IP candidates passively — unproxied in-scope subdomains, SPF `ip4:`/`ip6:`
literals, MX host IPs, and a Shodan `ssl.cert.subject.CN` search — then (active
mode only) confirms a candidate from **the certificate it serves**, falling back
to a spoofed `Host` header. The cert is tried first because it is much stronger
evidence: an IP presenting a certificate that names the target *is* serving the
target, whereas the header test only says "answered without looking like
Cloudflare", which a shared host or default vhost can do by accident. A cert
match also settles it without sending a request past the handshake, so the
confirmed case touches the target less than it used to. Every
candidate IP is enriched with ASN/org (via IPinfo, if configured) so you can
immediately see whether a leaked origin sits on the client's own infrastructure
or a third party's. A confirmed origin is an **origin IP disclosure / WAF-bypass**
finding; the report includes a baseline CVSS vector and remediation (restrict
origin firewall to Cloudflare ranges / Authenticated Origin Pulls / cloudflared
tunnel).

**Favicon pivot (Shodan).** A custom favicon is a company fingerprint — hosts
serving the same icon are very likely the same org's, *even when their names look
nothing like the seed domains*, which is exactly the shadow estate ordinary
subdomain enum misses. lrecon hashes each live host's favicon (mmh3, the format
Shodan indexes) and searches `http.favicon.hash:` for others. Each match is
reported with the evidence needed to judge ownership — IP, hostnames, org, cert
CN, page title — and tagged **in-scope**, **cross-domain**, or **ip-only**;
Cloudflare hosts are flagged, not dropped, since an origin answering on a shared
icon is worth seeing. The table filters like the attack surface.

Two guards matter here:

- **Noise.** A stock favicon (default nginx, WordPress, a JS framework) matches
  tens of thousands of unrelated hosts. Shodan reports the total up front, so a
  hash exceeding **500 matches** is skipped with a line saying so — a skipped
  framework default never reads as "no shadow assets".
- **Scope.** A shared icon is *evidence* of common ownership, never proof, and
  cross-domain matches are outside the seed domains — i.e. outside the SOW until
  you confirm otherwise. lrecon reports them either way but **never probes** them
  unless you pass `--favicon-expand`, which pulls the cross-domain matches into
  the active phase and logs a one-line ROE warning naming the count. The
  boundary check is the same label-anchored one every enum source uses, so a
  lookalike like `notacme.com` is never mistaken for in-scope. `--passive-only`
  never probes regardless of the flag.

**Tech-stack confirmation for CVE hits.** Shodan/InternetDB CVE data comes
from a periodic internet-wide scan that can be weeks old. Where a live
tech-detect probe is available (ProjectDiscovery `httpx -td`, Wappalyzer-based —
see [Optional backends](#optional-backends-projectdiscovery--psql)), lrecon
cross-references each host's reported CPEs against what's actually being
served right now and marks the CVE hit **tech-confirmed** (still corroborated)
or **unconfirmed** (no live match — banner may be stale, or the software's
been patched/replaced). Without the `httpx` binary the built-in probe supplies
`Server`/`X-Powered-By` instead — coarser than Wappalyzer fingerprinting, but
enough to compare against, so confirmation still runs; `lrecon --check-backends`
tells you whether `httpx` is on PATH.

**Confirmation gates promotion to an entry point.** An entry point asserts
something is worth working *now*, and that rests on the vulnerable software
actually being there:

| State | Meaning | Entry point |
|---|---|---|
| **confirmed** | the live probe corroborates the reported CPE | full CVSS-derived severity, up to `critical` |
| **unconfirmed** | the probe looked and found no matching software | **none** — sending someone to exploit software that isn't running is worse than saying nothing |
| **unverified** | nothing to compare (host never answered, or no CPEs reported) | kept, but capped at `high` |

The distinction between the last two matters: "we looked and it's not there" is
evidence, "we couldn't look" is not. An unverified host can still be hiding a
real critical behind a non-web port, so it stays on the list — just not at the
top of it. Nothing is ever dropped from the **CVE hits** table or the JSON;
this only changes what gets promoted into the priority summary.

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

**Domain-registration checks (T1590.001 / T1591).** The WHOIS/RDAP data every
run already collects (see [Domain registration](#domain-registration-whoisrdap))
is turned into ranked entry-points findings — no extra network calls:
- **`whois-domain-expiring`** — registration expires within 30 days (**medium**,
  or **high** within 7 days), an operational risk to flag to the client.
- **`whois-domain-expired`** — registration has already lapsed (**high**): a
  re-registration/takeover vector as well as an outage risk.
- **`whois-registrant-exposed`** — WHOIS privacy is off and a real registrant
  name/org is disclosed (**info**): harvestable identity/org OSINT for the
  engagement. Privacy-protected or unknown-registrant domains produce nothing.

**Live nuclei progress.** A `--nuclei` scan against many live hosts can run
for minutes with the stock backend giving zero feedback until it finishes.
lrecon runs nuclei with `-stats` and streams its periodic scan-status lines
(duration, hosts, requests, rps) straight to the console as they arrive,
instead of buffering all output until the process exits — a long scan no
longer looks hung.

---

## People OSINT (user enumeration)

Builds a red-team phishing/password-spray candidate list — **company-affiliated
data only**, never personal accounts or personal contact info. Output goes to
`<out>.users.csv`, a People section in the Markdown/HTML reports, and the
`people` block in the JSON.

| Source | What it gives you | Notes |
|---|---|---|
| **Website scrape** | addresses the target published on its own pages | **keyless**, runs on any active scope |
| **Hunter.io** | known company emails + the detected naming pattern (e.g. `{first}.{last}`) | official domain-search API |
| **GitHub** | company emails leaked in public commit/code history | reuses your `GITHUB_TOKEN`; shares the code-search rate limit with `--github` dorking |
| **RocketReach** | name + title (no email) via their official search API | see caveat below |

The keyed sources follow the usual "presence of a key = opt-in" convention. The
website scrape needs no key and runs on any active scope, because otherwise a
scope with no API keys produced an empty people list that read as *"nobody is
exposed"* when in truth nothing had been looked at. It fetches a short list of
likely contact paths (`/`, `/contact`, `/about`, `/team`, `/imprint`, …) on a few
in-scope live hosts — contact-page discovery, not a crawl — and is skipped under
`--passive-only` since it touches the target. Only addresses **at the in-scope
domain** are kept: a vendor's address in a footer is that vendor's exposure, and
collecting it would put out-of-scope people in a client deliverable.

**Individuals vs shared mailboxes.** The report counts them separately, because
"how many of our users are exposed" is a headcount question and `info@`/`noreply@`
is not headcount. Only mailboxes matching lrecon's known role names are split
out, so a mailing list or alias still counts as individual — read the first
figure as a floor on exposed addresses rather than a verified headcount.

**When a keyed source returns nothing, it says why.** Hunter answers both "this
domain has nothing indexed" and "your account is out of credits" with a `200` and
an empty list; lrecon logs the distinction (including Hunter's own error text)
instead of letting an exhausted account read as a clean result.

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

## AI-assisted dossier engine (LLM synthesis)

lrecon can synthesize a structured **target dossier** — company profile, tech
stack, entry points, authentication surface, and passive people OSINT — from the
data the pipeline already collects, with narrative sections written by an LLM
backend. Everything the dossier reports is derived from the recon pass; the LLM
only summarizes collected facts.

### Subcommands

```bash
# Recon, then emit a dossier (JSON + Markdown) alongside the usual outputs
lrecon dossier --company "Acme Corp" acme.com
lrecon full-report --company "Acme Corp" acme.com        # same pipeline

# Passive company-email / people OSINT only (no full recon)
lrecon enum --company "Acme Corp" acme.com --verify-emails

# Probe the configured LLM backend and exit
lrecon --check-llm
```

The default invocation (`lrecon acme.com …`) is unchanged — the subcommands are
additive.

### Swappable LLM backends

Provider-neutral, spoken over the same httpx client as everything else (no vendor
SDK is added to the dependency set). One OpenAI-compatible adapter covers OpenAI,
Ollama, LM Studio, and vLLM; Anthropic and Google have their own adapters.
Configured via `--llm-provider`/`--llm-model`/`--llm-base-url` or the `llm`
section of `config.json`:

```json
{
  "llm": {
    "provider": "ollama",
    "model": "llama3.1",
    "base_url": "http://127.0.0.1:11434/v1",
    "temperature": 0.2,
    "max_tokens": 1024,
    "per_module": { "news": { "model": "llama3.1", "max_tokens": 512 } },
    "news": { "sources": ["https://example.com/press.json"] }
  }
}
```

Cloud-provider keys come from `openai_api_key` / `anthropic_api_key` /
`google_ai_api_key` in `config.json`, or `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` /
`GOOGLE_AI_API_KEY` in the environment.

**No-exfiltration default.** The default provider is **local** (Ollama on
`127.0.0.1`); recon data leaves the operator's machine only when a cloud provider
is explicitly configured, and whenever a cloud provider is active lrecon logs a
one-line egress notice so it's never silent. If no LLM backend is reachable the
dossier still writes — with structured findings and empty narrative fields, so
the JSON stays machine-consumable.

### Factual company intel

The dossier's company-profile section pulls recent public records — **SEC EDGAR**
full-text search (public, keyless) plus any extra JSON/RSS endpoints the operator
lists under `llm.news.sources` — and has the LLM condense them into a neutral
factual summary and event buckets (`m&a`, `exec-change`, `product`,
`office-move`, `security-incident`, `tech-migration`). Every source is off unless
reachable/configured.

### Intentionally not built

This is a reconnaissance dossier engine. It does **not** generate phishing or
social-engineering pretext/lure content (no email bodies, spoofed senders,
urgency hooks, or impersonation), does **not** score findings for "pretext
potential," and does **not** perform active credential-oracle account
enumeration (forgot-password differential, login timing, OAuth-error, or
O365/Azure user-validation). Those capabilities are out of scope by design; the
passive people OSINT above and the operator-gated `--verify-emails` SMTP probe
are the only account-related features.

---

## Search-engine dorking

Finds exposed admin/login panels, config/env files, directory listings, and
`.git`/backup leaks indexed by Google against each in-scope domain — the
`site:` dork techniques security testers run by hand, automated across
seven curated categories per domain (admin/login panels, config/env
exposure, directory listing, backup/database files, exposed `.git`,
API/swagger docs, debug/error pages). Findings feed the entry-points
summary tagged **T1593.002** (Search Open Websites/Domains: Search Engines).

Opt-in via **`--dork`**. It's an explicit flag even when a key is configured
— unlike the "presence of a key = opt-in" convention used for the People
OSINT sources — because the free quotas are tight (Google CSE 100 queries/day,
Brave 2k/month) and each domain burns ~7 queries; auto-running it could
silently exhaust the allowance on a run where you didn't need it.

**Three interchangeable backends.** Pick one with `--dork-provider`
(`auto`/`google`/`brave`/`vertex`); `auto` uses whichever is configured,
preferring Google CSE so existing key-holders keep their current behavior.

**Automatic failover.** With more than one backend configured, `auto` falls
through to the next one when a backend fails *terminally* — a revoked key, an
exhausted quota, a rejected request. Since Google CSE is closed to new customers,
a stale CSE key sitting beside a working Brave key is a realistic setup, and it
would otherwise produce zero hits for the whole run. Failover resumes at the
domain that failed (earlier domains were already swept), hits are deduped by URL
across backends, and the startup line names the fallback chain. Quota use is
unchanged when the first backend works, since nothing else is queried. Pinning a
backend explicitly with `--dork-provider` never falls back.

| Backend | Flag / env | Credentials | Notes |
|---|---|---|---|
| **google** | `--google-cse-key` + `--google-cse-cx` (`GOOGLE_CSE_KEY`/`GOOGLE_CSE_CX`) | API key + Custom Search Engine ID | Google Custom Search JSON API. **Closed to new customers** (2025) — existing keys keep working, but new users can't sign up. |
| **brave** | `--brave-key` (`BRAVE_SEARCH_API_KEY`/`BRAVE_API_KEY`) | one API key | **Brave Search API** — the easiest replacement to obtain: free self-serve signup, a single key, plain REST, native `site:` support. Recommended for new users. |
| **vertex** | `--vertex-access-token` + `--vertex-project` + `--vertex-engine` *or* `--vertex-datastore` (+ optional `--vertex-location`, default `global`) | OAuth access token + GCP project + Search app/data store | **Vertex AI Search** (Discovery Engine) — Google's official CSE successor for site-restricted search (up to 50 domains per data store). Mint the token with `gcloud auth print-access-token` (`VERTEX_ACCESS_TOKEN`/`GOOGLE_ACCESS_TOKEN`); no service-account SDK is added. |

All three take the same config-file/env/CLI precedence as every other key.
For Vertex, config.json uses a `"vertex": { "access_token": …, "project": …,
"engine": … }` object.

**Result scoping.** Google CSE constrains results at the API level
(`siteSearchFilter`); Brave and Vertex are additionally post-filtered by each
hit's host, so a result only counts when its hostname is the target domain or
a subdomain of it — regardless of how a search engine's query-operator
precedence handles the `site:` in an `OR`-containing dork.

**No raw search-engine scraping.** Like the [People OSINT](#people-osint-user-enumeration)
LinkedIn decision above, lrecon does not scrape Google, Bing, or DuckDuckGo
HTML result pages directly — that means defeating anti-automation measures and
violating those platforms' terms of service. Every dork backend is an
official, keyed, documented search API.

A hit is a search-engine-indexed page matching a dork pattern, not a
confirmed live exposure — verify each is actually reachable before
reporting it, since a Google result can be stale.

## Domain registration (WHOIS/RDAP)

Every run looks up each domain's registration data — registrar, creation/
expiration dates, nameservers, and status codes — via **RDAP** (the
structured-JSON successor to WHOIS), queried keylessly over HTTPS through
`rdap.org`'s public bootstrap redirector to the authoritative registry. This
always runs, including under `--passive-only`, since it only touches
third-party registries/registrars, never the target's own infrastructure. A
domain expiring within 30 days — or already lapsed — is raised in the run log
**and surfaced as a ranked entry-points finding** (see below) so it lands in
the report and JSON, not just the console.

**No RDAP for a domain's TLD isn't a bug.** Checked against IANA's own
canonical RDAP bootstrap registry, several very common TLDs simply have no
RDAP service published at all — **`.io`, `.co`, `.me`**, and others — RDAP
just doesn't exist for them yet, at any registry. For those, lrecon falls
back through up to two further tiers, each only filling in fields the
previous tier didn't get, never overwriting a value an earlier tier already
found:

1. **Classic WHOIS** (port 43, RFC 3912) — a pure-Python socket client (no
   external `whois` binary — the "no system binary" design holds) asks
   `whois.iana.org` which registry WHOIS server is authoritative for the
   TLD, then queries it directly.
2. **VirusTotal's own cached WHOIS text**, if `--vt` is enabled and
   configured — parsed with the same logic as tier 1. This tier exists
   specifically because **raw TCP/port 43 is blocked outright in some
   sandboxed execution environments** — Claude Code's own remote/cloud
   containers included — regardless of the target TLD, so tier 1 silently
   comes back empty there no matter what. VT's text was fetched over
   HTTPS by an earlier phase, so it isn't subject to that restriction. If
   you're running lrecon inside one of these environments and still see no
   registrar for a domain with no RDAP, this is almost always why —
   passing `--vt` with a working key is the fix, not a bug report.

Both fallback tiers do free-text parsing, which is necessarily best-effort
— format varies by registry, unlike RDAP's structured JSON — so treat it as
a lead like everything else in the pipeline, not a certainty. Each domain's
report row carries a **Source** column listing every tier that actually
contributed a value (`RDAP`, `WHOIS (port 43)`, `VT WHOIS mirror`, or a
combination like `RDAP + VT WHOIS mirror`) so it's clear which method(s)
produced the data. If every tier came back empty for a domain but `--vt`
still has cached WHOIS text for it (rare — usually means the text didn't
match any of the parser's known field-label formats), that raw text is
shown as an unparsed, collapsible cross-reference in this section so you
can read it yourself.

Every in-scope domain gets a row in the report's "Domain registration
(WHOIS/RDAP)" section, even if every lookup came back empty (unsupported
TLD with no WHOIS referral either, typo, transient failure) — check the
run log for a `whois/rdap` line when a domain shows all `—`.

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
  resolution VT has observed, newest first, each with a first-seen date, **plus
  org / country / rDNS per address**. A bare list of IPs and dates says a
  domain moved, not what it moved between; the org is what makes the history
  readable — a former colo or cloud tenancy is a very different story from a
  former CDN. One IPinfo lookup per unique address, deduped across domains, and
  keyless (IPinfo answers unauthenticated at a lower rate limit).
- **Origin candidates** — an address a **currently Cloudflare-fronted** domain
  used to answer on directly is flagged: a plausible unproxied origin, the same
  thing the [Cloudflare origin phase](#cloudflare-origin-exposure) hunts for,
  reached through passive history instead of active probing. Three conditions
  all have to hold — the domain is CDN-fronted *today* (decided per domain from
  its own live IPs), the historical address is not itself Cloudflare, and it is
  not still live *for that domain*. Without the first, every past address of an
  unproxied domain becomes an "origin", which is just a hosting change with a
  scary label; without the third, a shared IP in a multi-domain scope lets one
  domain's live set hide another's stale record. When a domain has no live IPs
  (`--passive-only` skips resolution) the check does not run, and the report
  says so rather than showing an empty column that reads as clean. Verify a
  candidate by fetching the IP with the target's `Host` header — it is a lead,
  not a conclusion, since a shared host or a reassigned cloud address looks
  identical from the outside.
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
