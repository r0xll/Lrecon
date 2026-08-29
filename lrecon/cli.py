from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .common import log, load_keys, DEFAULT_RESOLVERS, TOP_PORTS, _HAVE_DNS
from .core import run
from .sources import load_wordlist
from .dorking import configured_dork_providers, select_dork_provider
from .report import (write_markdown, write_html, write_live_hosts, write_csv, write_users_csv,
                     write_origin_ips, screenshot_hosts)
from .backends import available_backends
from . import backends
from . import cache
from . import llm as _llm

_SUBCOMMANDS = ("dossier", "enum", "full-report")


def read_domains_file(path: str) -> list:
    """One domain per line; blank lines and #-comments skipped."""
    return [ln.strip() for ln in Path(path).read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def merge_domains(positional: list, file_domains: list) -> list:
    """Union of positional args + file domains, deduped, order preserved."""
    return list(dict.fromkeys(list(positional) + list(file_domains)))


def split_targets(tokens: list, ip_cap: int) -> tuple:
    """Partition seed tokens into `(domains, ips)`.

    A token that parses as an IP address or CIDR *and* contains `.`/`:` is an IP
    target; everything else is a domain. The char gate guards the
    `ipaddress.ip_network("1")` -> `0.0.0.1/32` footgun: a domain fails the
    parse and a bare integer fails the char gate, so both stay domains. A single
    host (`/32`, `/128`, or a bare IP) contributes one address; a wider net is
    expanded via `.hosts()` and truncated to `ip_cap` (same truncate posture as
    `--asn-cap`). Both lists are deduped with order preserved.
    """
    import ipaddress
    domains, ips = [], []
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        if "." not in t and ":" not in t:
            domains.append(t)
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            domains.append(t)
            continue
        if net.num_addresses == 1:
            ips.append(str(net.network_address))
            continue
        hosts = net.hosts()
        added = 0
        for ip in hosts:
            if added >= ip_cap:
                log(f"[!] {t}: expands to {net.num_addresses} addresses — capped at "
                    f"{ip_cap} (raise with --ip-cap)")
                break
            ips.append(str(ip))
            added += 1
    return list(dict.fromkeys(domains)), list(dict.fromkeys(ips))


def apply_all_flag(args) -> None:
    """
    --all turns on every OSINT/informational check that's otherwise opt-in
    only due to quota/speed/binary availability, not ROE: --buckets, --dork,
    --vt, --nvd, --asn-expand. Each still auto-skips on its own with a log
    line if its key/binary isn't configured — this just flips the flag,
    same as passing it by hand.

    Deliberately does NOT touch --active-ports, --verify-emails, or
    --nuclei — all three send live traffic straight at target-owned
    infrastructure (a TCP port scan, an SMTP RCPT-TO probe of the target's
    own mail servers, and nuclei's templated HTTP requests — including
    exploit/auth-bypass probes — against the target's live hosts,
    core.py gates it behind `not args.passive_only` for exactly that
    reason, the same gate --active-ports uses). The README's ROE/Legal
    section calls this class of check out as needing conscious
    authorization, so --all must never silently enable any of them.
    """
    if not args.all:
        return
    args.buckets = True
    args.dork = True
    args.vt = True
    args.nvd = True
    args.asn_expand = True


def main() -> None:
    """Dispatch subcommands (dossier / enum / full-report), else run the
    default flat recon flow. The default path preserves the original
    invocation (`lrecon example.com …`) unchanged."""
    argv = sys.argv[1:]
    if argv and argv[0] == "enum":
        return _cmd_enum(argv[1:])
    emit_dossier = False
    if argv and argv[0] in ("dossier", "full-report"):
        emit_dossier = True
        argv = argv[1:]
    _recon(argv, emit_dossier=emit_dossier)


def _recon(argv=None, emit_dossier: bool = False) -> None:
    ap = argparse.ArgumentParser(description="LRecon (Let's Recon) v3.2 — external recon (authorized use only)")
    ap.add_argument("domains", nargs="*",
                    help="root domain(s) in scope; bare IPs and CIDRs (e.g. 203.0.113.9, "
                         "203.0.113.0/24) are also accepted and enriched/probed directly")
    ap.add_argument("-iL", "--domains-file",
                    help="read targets from a file, one per line (# comments and blank "
                         "lines skipped) — domains, IPs and CIDRs; merged with any "
                         "positional targets, deduped")
    ap.add_argument("--check-backends", action="store_true",
                    help="validate optional backends (ProjectDiscovery tools + psql) + "
                         "parser mapping, then exit")
    ap.add_argument("--check-active", action="store_true",
                    help="with --check-backends: let naabu/nuclei test-scan scanme.nmap.org")
    ap.add_argument("--passive-only", action="store_true",
                    help="OSINT sources + host lookup only; no resolution/HTTP/portscan")
    ap.add_argument("--all", action="store_true",
                    help="turn on every OSINT/informational check that's otherwise opt-in due "
                         "to quota/speed/binary availability, not ROE: --buckets, --dork, --vt, "
                         "--nvd, --asn-expand (each still auto-skips with a log line if its "
                         "key/binary isn't configured). Does NOT enable --active-ports, "
                         "--verify-emails, or --nuclei — those send live traffic straight at "
                         "target-owned infrastructure and stay explicit opt-in regardless of --all")
    ap.add_argument("--no-cf-origin", action="store_true",
                    help="disable Cloudflare origin-IP discovery")
    ap.add_argument("--active-ports", action="store_true",
                    help="async TCP connect scan of common ports (aggressive; ROE-gated)")
    ap.add_argument("--ports", help="comma-separated ports for --active-ports")
    ap.add_argument("--no-banners", action="store_true",
                    help="with --active-ports, skip grabbing service banners (SSH/TLS/"
                         "greeting) on the open ports")
    ap.add_argument("--brute", action="store_true",
                    help="active DNS brute-force + permutation of the seed domains "
                         "(aggressive; ROE-gated — sends many queries at the domain's "
                         "authoritative NS). Resolved hits are wildcard-filtered like any "
                         "other host. Never enabled by --all")
    ap.add_argument("--wordlist",
                    help="subdomain wordlist for --brute (one label per line); defaults to a "
                         "compact bundled list — point at a SecLists file for depth")
    ap.add_argument("--brute-cap", type=int, default=5000,
                    help="max brute-force candidate names to resolve (default 5000)")
    ap.add_argument("--wayback-paths", action="store_true",
                    help="mine archived URL paths from the Wayback Machine and re-request "
                         "them on live hosts to surface forgotten admin panels / old apps "
                         "(aggressive; ROE-gated — sends live HTTP at the target). Never "
                         "enabled by --all")
    ap.add_argument("--wayback-cap", type=int, default=400,
                    help="max archived paths to re-verify across all hosts (default 400)")
    ap.add_argument("--api-scan", action="store_true",
                    help="on live hosts, probe common API-doc routes (openapi/swagger/"
                         "graphql) and scan same-origin JS bundles for secret leads "
                         "(aggressive; ROE-gated — fetches from the target). Never "
                         "enabled by --all")
    ap.add_argument("--js-max", type=int, default=8,
                    help="max same-origin JS bundles to scan per host for --api-scan (default 8)")
    ap.add_argument("--asn-expand", action="store_true",
                    help="expand scope via ASN->netblocks + reverse-DNS sweep (aggressive)")
    ap.add_argument("--asn-cap", type=int, default=4096, help="max PTR lookups for --asn-expand")
    ap.add_argument("--ip-cap", type=int, default=1024,
                    help="max host addresses to expand from a single CIDR target (default 1024)")
    ap.add_argument("--favicon-expand", action="store_true",
                    help="actively probe hosts on OTHER domains that share a target favicon "
                         "(needs Shodan; ROE-gated — a shared icon is weak ownership evidence, "
                         "so confirm the matches are in your SOW). Off by default: matches are "
                         "reported with evidence either way, this only controls probing them")
    ap.add_argument("--buckets", action="store_true", help="cloud bucket permutation enum")
    ap.add_argument("--bucket-keywords", help="extra comma-separated bucket keywords")
    ap.add_argument("--dork", action="store_true",
                    help="search-engine dork for exposed admin/login panels, config/env files, "
                         "directory listings, .git/backup leaks, etc. (~7 queries per domain; "
                         "explicit flag even with a key configured, since free quotas are tight). "
                         "Backend auto-selected from configured creds — see --dork-provider")
    ap.add_argument("--dork-provider", choices=["auto", "google", "brave", "vertex"],
                    default="auto",
                    help="dork search backend: google (Custom Search JSON API — closed to new "
                         "customers), brave (Brave Search API — easiest free signup), vertex "
                         "(Vertex AI Search / Discovery Engine). 'auto' picks the first configured, "
                         "preferring google for existing key-holders")
    ap.add_argument("--google-cse-key", help="Google Custom Search API key (else env/config)")
    ap.add_argument("--google-cse-cx", help="Google Custom Search Engine ID (else env/config)")
    ap.add_argument("--brave-key", help="Brave Search API key (else BRAVE_SEARCH_API_KEY/config)")
    ap.add_argument("--vertex-access-token",
                    help="Vertex AI Search OAuth access token, e.g. `gcloud auth "
                         "print-access-token` (else VERTEX_ACCESS_TOKEN/GOOGLE_ACCESS_TOKEN/config)")
    ap.add_argument("--vertex-project", help="Vertex AI Search GCP project (else env/config)")
    ap.add_argument("--vertex-location", help="Vertex AI Search location (default 'global')")
    ap.add_argument("--vertex-engine", help="Vertex AI Search engine/app ID (else env/config)")
    ap.add_argument("--vertex-datastore",
                    help="Vertex AI Search data-store ID (used if --vertex-engine unset)")
    ap.add_argument("--vt", action="store_true",
                    help="VirusTotal domain intelligence: historical IP resolutions "
                         "(hosting history), WHOIS mirror, DNS-record snapshot, reputation "
                         "(needs --vt-key; free tier is 4 req/min, 2 calls/domain — explicit "
                         "flag even with a key configured, since it adds real wall-clock time)")
    ap.add_argument("--vt-key", help="VirusTotal API key (else env/config)")
    ap.add_argument("--otx-key", help="AlienVault OTX API key (else OTX_API_KEY/config). "
                                      "OTX refuses anonymous passive-DNS queries, so this "
                                      "source contributes nothing without one")
    ap.add_argument("--nvd", action="store_true", help="resolve CPEs to CVEs via NVD (slow)")
    ap.add_argument("--nvd-max-cves", type=int, default=25,
                    help="per-host cap on bare Shodan/InternetDB CVE IDs resolved via NVD "
                         "for CVSS/severity/description (default 25; raise for hosts with many "
                         "reported CVEs at the cost of more rate-limited NVD requests)")
    ap.add_argument("--nuclei", action="store_true",
                    help="run nuclei templated vuln scan on live hosts (needs nuclei binary)")
    ap.add_argument("--nuclei-severity", help="min nuclei severity (e.g. medium,high,critical)")
    ap.add_argument("--no-cache", action="store_true",
                    help="bypass the on-disk enrichment cache — always fetch fresh "
                         "(IPinfo/Shodan/NVD/KEV/EPSS/VT)")
    ap.add_argument("--cache-ttl", type=int,
                    help="override the enrichment-cache TTL in seconds for all namespaces")
    ap.add_argument("--no-pd", action="store_true",
                    help="force pure-Python/HTTP paths; ignore ProjectDiscovery binaries "
                         "and the psql-based crt.sh direct-DB accelerator")
    ap.add_argument("--diff", action="store_true", help="diff against previous run snapshot")
    ap.add_argument("--screenshots", action="store_true",
                    help="capture live-host screenshots (needs playwright)")
    ap.add_argument("--resolvers", help=f"comma-separated DNS servers (default {','.join(DEFAULT_RESOLVERS)})")
    ap.add_argument("--shodan-key", help="Shodan API key (else env/config)")
    ap.add_argument("--ipinfo-key", help="IPinfo token (else env/config)")
    ap.add_argument("--hunter-key", help="Hunter.io API key — company email OSINT (else env/config)")
    ap.add_argument("--rocketreach-key", help="RocketReach API key — company people OSINT (else env/config)")
    ap.add_argument("--company-name",
                    help="company name override for people-enum sources that search by name "
                         "rather than domain (e.g. RocketReach); defaults to the domain's label")
    ap.add_argument("--verify-emails", action="store_true",
                    help="SMTP RCPT-TO probe discovered company emails against the domain's MX "
                         "(active — touches target mail infra; detects and flags catch-all domains "
                         "rather than reporting false positives)")
    ap.add_argument("--ask-keys", action="store_true", help="prompt for keys via getpass")
    ap.add_argument("--config", help="config json path (default ~/.config/lrecon/config.json)")
    # ---- LLM (dossier/news synthesis; see the dossier/full-report subcommands) ----
    ap.add_argument("--llm-provider",
                    help="LLM provider for dossier/news synthesis: ollama|lmstudio|vllm|"
                         "openai|anthropic|google (default ollama — local, no data leaves the host)")
    ap.add_argument("--llm-model", help="LLM model id (else config.json llm.model)")
    ap.add_argument("--llm-base-url", help="LLM endpoint base URL (else provider default)")
    ap.add_argument("--check-llm", action="store_true",
                    help="probe the configured LLM backend for reachability, then exit")
    ap.add_argument("--company",
                    help="company name (alias for --company-name; used by the dossier "
                         "subcommand and RocketReach people-enum)")
    ap.add_argument("--domain", action="append", dest="extra_domains",
                    help="in-scope domain (repeatable); merged with positional domains and -iL")
    ap.add_argument("-c", "--concurrency", type=int, default=50)
    ap.add_argument("--no-progress", action="store_true")
    ap.add_argument("-o", "--out", default="lrecon",
                    help="output basename — a UTC timestamp is appended so "
                         "reruns don't overwrite prior output (<basename>_YYYYMMDD_HHMMSS.*)")
    args = ap.parse_args(argv)
    apply_all_flag(args)
    # --company is an alias for --company-name; --domain appends to positional.
    if getattr(args, "company", None) and not args.company_name:
        args.company_name = args.company
    if getattr(args, "extra_domains", None):
        args.domains = merge_domains(args.domains, args.extra_domains)

    if getattr(args, "check_llm", False):
        keys = load_keys(args)
        cfg = _llm.config_from_keys(keys)
        row = asyncio.run(_check_llm(cfg))
        log(f"[i] LLM backend self-check: provider={row['provider']} model={row['model']} "
            f"base_url={row['base_url']}")
        log(f"    reachable={'yes' if row['reachable'] else ' no'}  note: {row['note']}")
        return

    if args.check_backends:
        rows = asyncio.run(backends.selfcheck(active=args.check_active))
        w = max(len(r["tool"]) for r in rows)
        log("[i] backend self-check" + (" (active test-scan)" if args.check_active else ""))
        log(f"    {'TOOL'.ljust(w)}  PATH  RAN  PARSED  NOTE")
        for r in rows:
            log(f"    {r['tool'].ljust(w)}  "
                f"{'yes' if r['path'] else ' no'}   "
                f"{'yes' if r['ran'] else ' no'}  "
                f"{str(r['parsed']).rjust(6)}  {r['note']}")
        broken = [r for r in rows if r["path"] and not r["ran"]]
        if broken:
            log(f"[!] {len(broken)} backend(s) present but failed to run/parse — "
                "check binary version vs parser in backends.py")
        return

    if args.domains_file:
        try:
            file_domains = read_domains_file(args.domains_file)
        except OSError as e:
            ap.error(f"--domains-file: {e}")
        args.domains = merge_domains(args.domains, file_domains)

    # Split IPs/CIDRs out of the seed list into their own lane — they skip
    # subdomain enumeration and DNS resolution and join the pipeline at the
    # (already IP-keyed) enrichment phase. Keeping them out of args.domains is
    # load-bearing: every domain-scoped step (whois, wildcard, www favicon
    # seeding, endswith scope checks) would choke on an IP literal.
    args.domains, args.ip_targets = split_targets(args.domains, args.ip_cap)
    if args.ip_targets:
        log(f"[i] {len(args.ip_targets)} IP target(s) in scope — enriched and probed "
            f"directly, no subdomain enumeration")

    if not args.domains and not args.ip_targets:
        ap.error("provide at least one domain or IP/CIDR (or use --check-backends)")

    if args.active_ports and args.passive_only:
        ap.error("--active-ports conflicts with --passive-only")
    if args.verify_emails and args.passive_only:
        ap.error("--verify-emails conflicts with --passive-only (it opens an SMTP "
                 "connection to the target's own MX)")
    if args.brute and args.passive_only:
        ap.error("--brute conflicts with --passive-only (it sends active DNS queries "
                 "at the target's authoritative nameservers)")
    if args.wayback_paths and args.passive_only:
        ap.error("--wayback-paths conflicts with --passive-only (it re-requests archived "
                 "paths live against the target)")
    if args.api_scan and args.passive_only:
        ap.error("--api-scan conflicts with --passive-only (it fetches API docs and JS "
                 "bundles live from the target)")
    # Load the brute wordlist up front so a bad --wordlist path fails fast, not
    # mid-run. args.brute_words is the resolved label list core.run() uses.
    args.brute_words = []
    if args.brute:
        try:
            args.brute_words = load_wordlist(args.wordlist)
        except OSError as e:
            ap.error(f"--wordlist: {e}")
        log(f"[i] --brute: {len(args.brute_words)} wordlist label(s) loaded"
            + (f" from {args.wordlist}" if args.wordlist else " (bundled default)"))
    args.ports = [int(p) for p in args.ports.split(",")] if args.ports else TOP_PORTS

    if not _HAVE_DNS and not args.passive_only:
        log("[!] dnspython missing — install it or use --passive-only")

    keys = load_keys(args)
    if args.all:
        log("[i] --all: enabling --buckets --dork --vt --nvd --asn-expand "
            "(each still skips on its own if a needed key/binary isn't configured; "
            "--active-ports/--verify-emails/--nuclei stay opt-in — they touch target infra)")
    log(f"[i] enrichment: ports/CVE via {'Shodan' if keys['shodan'] else 'InternetDB (keyless)'}"
        f" | ASN/org/rDNS via IPinfo ({'key' if keys['ipinfo'] else 'keyless, lower rate limit'})"
        f" | github {'on' if keys['github'] else 'off'}"
        f" | hibp {'key' if keys['hibp'] else 'keyless'}")
    people_sources = [n for n, k in (("hunter", keys["hunter"]), ("rocketreach", keys["rocketreach"]),
                                     ("github", keys["github"])) if k]
    # The website scrape needs no key, so people-enum is never fully "off" on an
    # active run — saying otherwise told operators not to expect results they
    # were about to get.
    if not args.passive_only:
        people_sources.append("website (keyless)")
    log(f"[i] people-enum: {', '.join(people_sources) if people_sources else 'off (no key, and --passive-only skips the website scrape)'}"
        f" | email verify: {'on (active)' if args.verify_emails else 'off'}")
    if args.dork:
        chain = configured_dork_providers(keys, args.dork_provider)
        if chain:
            # Name the whole chain so the operator knows a dead first backend
            # won't sink the sweep — failover only triggers on a terminal error.
            log(f"[i] dork: on (backend: {chain[0]}"
                + (f", fallback: {' -> '.join(chain[1:])}" if len(chain) > 1 else "")
                + ")")
        elif args.dork_provider != "auto":
            log(f"[i] dork: requested backend '{args.dork_provider}' not configured — will skip")
        else:
            log("[i] dork: requested but no search backend configured "
                "(google-cse / brave / vertex) — will skip")
    if args.vt:
        log(f"[i] VirusTotal domain intel: {'on' if keys['vt'] else 'requested but not configured — will skip'}")
    if args.no_pd:
        log("[i] backends: forced pure-Python (--no-pd)")
    else:
        bk = available_backends()
        active = [t for t, ok in bk.items() if ok]
        log(f"[i] optional backends: {', '.join(active) if active else 'none on PATH (pure-Python)'}")

    cache.configure(enabled=not args.no_cache, ttl_override=args.cache_ttl)
    if args.no_cache:
        log("[i] enrichment cache: disabled (--no-cache)")

    t0 = time.time()
    res = asyncio.run(run(args.domains, args, keys))
    hosts = res["hosts"]
    cst = cache.stats()
    if not args.no_cache and (cst["hit"] or cst["miss"]):
        log(f"[i] enrichment cache: {cst['hit']} hit(s), {cst['miss']} miss(es)")

    out_base = f"{args.out}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    json_path = f"{out_base}.json"
    md_path = f"{out_base}.md"
    html_path = f"{out_base}.html"
    live_path = f"{out_base}.live.txt"
    csv_path = f"{out_base}.targets.csv"
    users_path = f"{out_base}.users.csv"
    origin_path = f"{out_base}.origin_ips.txt"

    # Every result key the JSON export carries. Anything added to run()'s return
    # value has to be listed here too, or it renders in the Markdown/HTML report
    # but silently vanishes from the machine-readable output.
    full = {k: res.get(k) for k in ("cf", "email", "github", "buckets", "breach",
                                    "asn", "favicon_pivots", "nuclei", "diff", "per_source",
                                    "entry_points", "whois", "dorks", "dns", "mail_infra", "vt",
                                    "auth_surface", "certs", "axfr", "security_txt",
                                    "tracking_correlation")}
    full["hosts"] = [h.to_dict() for h in hosts]
    full["people"] = [p.to_dict() for p in res.get("people") or []]
    Path(json_path).write_text(json.dumps(full, indent=2, default=str))
    write_markdown(hosts, args.domains, res, md_path)
    write_html(hosts, args.domains, res, html_path)
    n_live = write_live_hosts(hosts, live_path)
    n_targets = write_csv(hosts, csv_path)
    # Say what was left off the scope sheet, so a shorter list never reads as
    # "nothing found" — same reasoning as the passive-source failure lines. Only
    # confirmed-NXDOMAIN hosts are excluded as dead; a timeout/SERVFAIL host
    # stays on the sheet as `unresolved` rather than being wrongly dropped.
    n_dead = sum(1 for h in hosts if h.nxdomain and not h.wildcard)
    n_wild = sum(1 for h in hosts if h.wildcard)
    if n_dead or n_wild:
        log(f"[i] scope sheet ({csv_path.split('/')[-1]}): excluded "
            f"{n_dead} non-existent (NXDOMAIN) and {n_wild} wildcard host(s) — they "
            f"remain in the full report/JSON, just not on the approval list")

    outputs = [json_path, md_path, html_path, live_path, csv_path]
    people = res.get("people") or []
    if people:
        write_users_csv(people, users_path)
        outputs.append(users_path)
    n_origin = write_origin_ips(res.get("cf") or {}, origin_path)
    if n_origin:
        outputs.append(origin_path)
    if args.screenshots:
        urls = [l for l in Path(live_path).read_text().splitlines() if l]
        shot_dir = f"{out_base}_shots"
        n = asyncio.run(screenshot_hosts(urls, shot_dir))
        if n:
            outputs.append(shot_dir + "/")
            log(f"[+] {n} screenshot(s) -> {shot_dir}/")

    if emit_dossier:
        outputs += _emit_dossier(res, args, keys, out_base)

    n_entry = len(res.get("entry_points") or [])
    n_dorks = len(res.get("dorks") or [])
    log(f"[+] done in {time.time()-t0:.1f}s — {len(hosts)} hosts, {n_live} live URLs, "
        f"{n_entry} potential entry point(s), {len(people)} enumerated user(s), {n_dorks} dork hit(s), "
        f"{n_origin} CF-origin candidate IP(s)")
    log(f"[+] {'  '.join(outputs)}")


# --------------------------------------------------------------------------- #
# LLM / dossier helpers + subcommands
# --------------------------------------------------------------------------- #
async def _check_llm(cfg) -> dict:
    import httpx
    async with httpx.AsyncClient(verify=True) as client:
        return await _llm.check_llm(client, cfg)


async def _build_dossier_async(res, args, keys, out_base) -> list:
    import httpx
    from . import dossier as _dossier
    from . import news as _news
    from .common import RateLimiter
    cfg = _llm.config_from_keys(keys)
    company = args.company_name or (args.domains[0].split(".")[0] if args.domains else "target")
    headers = {"User-Agent": "lrecon/3.2 (authorized-assessment)"}
    async with httpx.AsyncClient(headers=headers, verify=True) as client:
        # Factual company intel (SEC EDGAR + operator-supplied sources).
        news = None
        try:
            extra = ((keys.get("llm") or {}).get("news") or {}).get("sources")
        except Exception:
            extra = None
        limiter = RateLimiter(2.0)
        news = await _news.company_intel(client, company, args.domains[0] if args.domains else "",
                                         cfg, extra_sources=extra, limiter=limiter)
        dossier = await _dossier.build_dossier(client, res, args.domains, company,
                                               llm_cfg=cfg, news=news)
    dj = f"{out_base}.dossier.json"
    dm = f"{out_base}.dossier.md"
    _dossier.write_dossier_json(dossier, dj)
    _dossier.write_dossier_md(dossier, dm)
    log(f"[+] dossier: {'LLM-synthesized' if dossier.get('generated_with_llm') else 'structured-only'} "
        f"-> {dm}")
    return [dj, dm]


def _emit_dossier(res, args, keys, out_base) -> list:
    try:
        return asyncio.run(_build_dossier_async(res, args, keys, out_base))
    except Exception as e:
        log(f"[!] dossier generation failed: {e}")
        return []


def _cmd_enum(argv) -> None:
    """Passive company-email / people OSINT (Hunter.io, GitHub, RocketReach)
    without the full recon pipeline. --verify-emails keeps the existing
    operator-gated SMTP probe; no active credential-oracle enumeration."""
    import httpx
    from . import people as _people
    from .common import RateLimiter, DEFAULT_RESOLVERS as _DR
    ap = argparse.ArgumentParser(prog="lrecon enum",
                                 description="passive company email / people OSINT")
    ap.add_argument("domains", nargs="*", help="in-scope domain(s)")
    ap.add_argument("-d", "--domain", action="append", dest="extra_domains", help="domain (repeatable)")
    ap.add_argument("-iL", "--domains-file", help="read domains from a file")
    ap.add_argument("--names", help="optional newline-delimited name list for pattern generation")
    ap.add_argument("--company", dest="company_name", help="company name (RocketReach)")
    ap.add_argument("--company-name", dest="company_name", help=argparse.SUPPRESS)
    ap.add_argument("--verify-emails", action="store_true",
                    help="SMTP RCPT-TO probe (active; touches target MX)")
    ap.add_argument("--resolvers", help="comma-separated DNS servers")
    ap.add_argument("-o", "--out", default="lrecon", help="output basename")
    ap.add_argument("--config", help="config json path")
    ap.add_argument("--hunter-key")
    ap.add_argument("--rocketreach-key")
    # load_keys reads several attributes that this subparser doesn't define.
    for attr in ("shodan_key", "ipinfo_key", "vt_key", "google_cse_key", "google_cse_cx",
                 "brave_key", "vertex_access_token", "vertex_project", "vertex_location",
                 "vertex_engine", "vertex_datastore",
                 "ask_keys", "llm_provider", "llm_model", "llm_base_url"):
        ap.set_defaults(**{attr: None})
    args = ap.parse_args(argv)
    domains = list(args.domains)
    if args.extra_domains:
        domains = merge_domains(domains, args.extra_domains)
    if args.domains_file:
        try:
            domains = merge_domains(domains, read_domains_file(args.domains_file))
        except OSError as e:
            ap.error(f"--domains-file: {e}")
    if not domains:
        ap.error("provide at least one domain")
    args.domains = domains
    keys = load_keys(args)
    ns = args.resolvers.split(",") if args.resolvers else _DR

    async def _go():
        headers = {"User-Agent": "lrecon/3.2 (authorized-assessment)"}
        gh_limiter = RateLimiter(0.2)
        people = []
        async with httpx.AsyncClient(headers=headers, verify=True) as client:
            for d in domains:
                people += await _people.enumerate_people(client, d, keys, gh_limiter,
                                                         args.company_name)
        if args.verify_emails:
            for d in domains:
                d_people = [p for p in people if p.email.endswith(f"@{d}")]
                if not d_people:
                    continue
                statuses = await _people.verify_emails(d, [p.email for p in d_people], ns)
                for p in d_people:
                    p.smtp_status = statuses.get(p.email)
        return people

    people = asyncio.run(_go())
    out_base = f"{args.out}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    users_path = f"{out_base}.users.csv"
    json_path = f"{out_base}.users.json"
    write_users_csv(people, users_path)
    Path(json_path).write_text(json.dumps([p.to_dict() for p in people], indent=2, default=str))
    log(f"[+] enum: {len(people)} company-affiliated email(s) -> {users_path}  {json_path}")


if __name__ == "__main__":
    main()
