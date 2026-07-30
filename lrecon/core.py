from __future__ import annotations
import asyncio, ipaddress, json, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import httpx
from .common import *
from .sources import *
from .enrich import *
from .intel import *
from .active import *
from .state import *
from .people import *
from .dorking import *
from .vt import *
from . import backends
from . import tlsinfo
from .tlsinfo import TLS_PORTS, fetch_cert, in_scope_cert_names

# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _progress():
    return Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                    BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(), console=_console)


async def _gather_with_progress(coros, desc, use_progress):
    coros = list(coros)
    if use_progress and _HAVE_RICH:
        with _progress() as prog:
            task = prog.add_task(desc, total=len(coros))
            async def wrap(c):
                r = await c
                prog.advance(task)
                return r
            return await asyncio.gather(*(wrap(c) for c in coros))
    return await asyncio.gather(*coros)


async def verify_keys(client, keys: dict) -> None:
    """
    On-boot API key verification — one cheap, non-quota-consuming call per
    configured key (account-info endpoints where available, not the actual
    feature endpoints), so a bad/expired key surfaces immediately as
    "Invalid" instead of silently degrading whatever phase uses it later.
    Nulls out rejected keys in keys (in place) so the rest of the pipeline
    automatically falls back to keyless/skips that service, same as the
    prior Shodan-only check this replaces.
    """
    if keys.get("shodan"):
        try:
            r = await client.get(f"https://api.shodan.io/api-info?key={keys['shodan']}", timeout=15)
            if r.status_code == 200:
                log(f"[+] Shodan API: Ready — query credits: {r.json().get('query_credits', '?')}")
            elif r.status_code == 401:
                log("[!] Shodan API: Invalid — falling back to keyless InternetDB")
                keys["shodan"] = None
            else:
                log(f"[!] Shodan API: unexpected response (HTTP {r.status_code}) — proceeding anyway")
        except Exception as e:
            log(f"[!] Shodan API: check failed ({e}) — proceeding anyway")

    if keys.get("ipinfo"):
        try:
            r = await client.get("https://ipinfo.io/json", params={"token": keys["ipinfo"]}, timeout=15)
            body = r.json() if r.content else {}
            if r.status_code == 200 and "error" not in body:
                log("[+] IPinfo API: Ready")
            elif r.status_code in (401, 403) or "error" in body:
                log("[!] IPinfo API: Invalid — falling back to keyless (lower rate limit, "
                    "ASN/org/rDNS still enriched)")
                keys["ipinfo"] = None
            else:
                log(f"[!] IPinfo API: unexpected response (HTTP {r.status_code}) — proceeding anyway")
        except Exception as e:
            log(f"[!] IPinfo API: check failed ({e}) — proceeding anyway")

    if keys.get("github"):
        try:
            r = await client.get("https://api.github.com/user",
                                headers={"Authorization": f"Bearer {keys['github']}",
                                        "User-Agent": "lrecon"}, timeout=15)
            if r.status_code == 200:
                log(f"[+] GitHub API: Ready (as {r.json().get('login', '?')})")
            elif r.status_code == 401:
                log("[!] GitHub API: Invalid — code dorking / email harvest disabled")
                keys["github"] = None
            else:
                log(f"[!] GitHub API: unexpected response (HTTP {r.status_code}) — proceeding anyway")
        except Exception as e:
            log(f"[!] GitHub API: check failed ({e}) — proceeding anyway")

    if keys.get("hunter"):
        try:
            r = await client.get("https://api.hunter.io/v2/account",
                                params={"api_key": keys["hunter"]}, timeout=15)
            if r.status_code == 200:
                searches = r.json().get("data", {}).get("requests", {}).get("searches", {})
                left = searches.get("available", "?") if isinstance(searches, dict) else "?"
                log(f"[+] Hunter.io API: Ready — searches available: {left}")
            elif r.status_code in (401, 403):
                log("[!] Hunter.io API: Invalid — company email OSINT via Hunter disabled")
                keys["hunter"] = None
            else:
                log(f"[!] Hunter.io API: unexpected response (HTTP {r.status_code}) — proceeding anyway")
        except Exception as e:
            log(f"[!] Hunter.io API: check failed ({e}) — proceeding anyway")

    if keys.get("rocketreach"):
        try:
            r = await client.get("https://api.rocketreach.co/api/v2/account",
                                headers={"Api-Key": keys["rocketreach"]}, timeout=15)
            if r.status_code == 200:
                log("[+] RocketReach API: Ready")
            elif r.status_code in (401, 403):
                log("[!] RocketReach API: Invalid — company people search via RocketReach disabled")
                keys["rocketreach"] = None
            else:
                log(f"[!] RocketReach API: unexpected response (HTTP {r.status_code}) — proceeding anyway")
        except Exception as e:
            log(f"[!] RocketReach API: check failed ({e}) — proceeding anyway")

    if keys.get("hibp"):
        # hibp_breaches() only calls HIBP's keyless domain-breaches endpoint —
        # there's nothing keyed to verify here yet, so just say so plainly
        # rather than pretending to validate a key that isn't sent anywhere.
        log("[i] HIBP: key configured but not required — domain-breach lookup uses HIBP's keyless endpoint")


async def _run_dorks(client, domains, providers, keys, limiter) -> tuple:
    """Sweep every domain, falling back to the next configured search backend on
    a terminal failure. Returns (hits, providers_used).

    A terminal failure (revoked key, exhausted quota, malformed request) will
    recur identically for every remaining domain, so continuing with that
    backend is pointless — but giving up entirely wastes any other configured
    backend. Google CSE is closed to new customers, so a stale CSE key sitting
    alongside a working Brave key is a realistic setup, and it used to yield
    zero hits.

    Fallback resumes at the domain that failed rather than restarting: earlier
    domains completed, while the failing one aborted partway through its
    categories and still needs a full sweep. Hits are deduped by link across
    backends — _run_templates() only dedupes within a single domain, and two
    engines routinely index the same URL.
    """
    hits, used, seen = [], [], set()
    remaining = list(domains)
    for i, provider in enumerate(providers):
        exhausted = False
        while remaining:
            d = remaining[0]
            found, terminal = await dork_domain(client, d, provider, keys, limiter)
            for hit in found:
                if hit["link"] in seen:
                    continue
                seen.add(hit["link"])
                hits.append(hit)
                if provider not in used:
                    used.append(provider)
            if terminal:
                nxt = providers[i + 1] if i + 1 < len(providers) else None
                log(f"[!] {provider} dork: terminal failure on {d} — "
                    + (f"falling back to {nxt}" if nxt else
                       "no other search backend configured, giving up"))
                exhausted = True
                break
            remaining.pop(0)                  # this domain is fully swept
        if not exhausted:                     # every domain swept, nothing to fall back for
            break
    return hits, used


async def run(domains, args, keys) -> list:
    ns = args.resolvers.split(",") if args.resolvers else DEFAULT_RESOLVERS
    use_prog = _HAVE_RICH and not args.no_progress
    limits = httpx.Limits(max_connections=args.concurrency)
    headers = {"User-Agent": "lrecon/2.2 (authorized-assessment)"}
    shodan_limiter = RateLimiter(per_second=1.0)

    # `client` verifies certs — used for calls to trusted third-party APIs (Shodan,
    # IPinfo, GitHub, HIBP, NVD, crt.sh, etc.), several of which carry API keys/tokens.
    # `probe_client` skips verification — needed when touching engagement targets
    # directly (self-signed / mismatched certs are common there).
    async with httpx.AsyncClient(limits=limits, headers=headers, verify=True,
                                follow_redirects=False) as client, \
              httpx.AsyncClient(limits=limits, headers=headers, verify=False,
                                follow_redirects=False) as probe_client:

        await verify_keys(client, keys)
        shodan_key = keys.get("shodan")           # re-sync: verify_keys() may have nulled either
        ipinfo_token = keys.get("ipinfo")

        # ---- Phase 1: passive enum (with source attribution) ----
        host_sources, per_source = await passive_enum(client, domains, keys, no_pd=args.no_pd)
        hosts = {n: Host(subdomain=n, source=set(srcs)) for n, srcs in host_sources.items()}
        breakdown = "  ".join(f"{s}={per_source[s]}" for s in sorted(per_source)) or "none"
        log(f"[+] {len(hosts)} unique subdomains  |  by source: {breakdown}")
        if per_source.get("crtsh", 0) == 0:
            log("[!] crt.sh returned 0 — its frontend 502s/times out intermittently under "
                "load; both query forms were retried (see the crt.sh lines above for the "
                "per-attempt statuses). Other CT sources (certspotter/OTX) cover this; "
                "--no-pd skips the direct-Postgres tier if it is being slow.")

        # ---- VirusTotal domain intelligence (opt-in --vt; needs VT key) ----
        # Explicit flag even with a key configured — VT's free tier is
        # rate-limited to 4 req/min and each domain costs two calls, so
        # auto-running it would add real wall-clock time to every run.
        # Passive: only queries VT's own API, never the target directly —
        # same tier as --dork/--buckets, not gated behind --passive-only.
        # Runs ahead of the WHOIS/RDAP phase below (rather than later,
        # where it used to sit) because whois_lookup() uses VT's own
        # cached WHOIS text as its third fallback tier and needs it in hand.
        vt_intel = {}
        if args.vt:
            if keys.get("vt"):
                vt_limiter = RateLimiter(per_second=4 / 60)
                for d in domains:
                    info = await vt_domain_intel(client, d, keys["vt"], vt_limiter)
                    if info:
                        vt_intel[d] = info
                if vt_intel:
                    n_hist = sum(len(v.get("ip_history") or []) for v in vt_intel.values())
                    log(f"[+] VirusTotal: {len(vt_intel)} domain(s) enriched, "
                        f"{n_hist} historical IP resolution(s)")
            else:
                log("[!] --vt set but --vt-key/VT_API_KEY not configured — skipping")

        # ---- Domain registration data (WHOIS via RDAP, falling back to
        # classic WHOIS/port 43, then to --vt's cached WHOIS text, for
        # TLDs/environments where the earlier tiers come back empty —
        # .io/.co/.me and others have no RDAP at all (confirmed against
        # IANA's own bootstrap registry), and raw TCP/port 43 is blocked
        # outright in some sandboxed execution environments (including
        # Claude Code's own remote containers — see /root/.ccr/README.md's
        # "Not supported through the proxy: ... raw-TCP databases"), where
        # VT's HTTPS-fetched mirror is the only one of the three that can
        # actually reach the network) ----
        # Keyless (RDAP/WHOIS43 tiers), third-party-registry-only — runs
        # even in --passive-only, same tier as the passive-enum sources
        # above. Always records one entry per domain, even on a total
        # lookup failure (unsupported TLD, network issue, domain not
        # found) — a client running an engagement against N domains
        # should see all N in the WHOIS section, not have the whole
        # section vanish because one domain's lookup came back empty.
        whois = {}
        for d in domains:
            vt_whois_text = vt_intel.get(d, {}).get("whois")
            w = await whois_lookup(client, d, vt_whois_text)
            whois[d] = w
            if w.get("expires") and domain_expiring_soon(w["expires"]):
                log(f"[!] {d}: domain registration expires {w['expires']} — flag to client")

        # ---- Phase 2: resolution + wildcard filter ----
        if not args.passive_only:
            wildcard_ips = {d: await detect_wildcard(d, ns) for d in domains}

            def _mark_wildcard(h):
                root = next((d for d in domains if h.subdomain.endswith(d)), None)
                wc = wildcard_ips.get(root, set()) if root else set()
                if wc and h.ips and set(h.ips).issubset(wc):
                    h.wildcard = True

            use_dnsx = not args.no_pd
            dnsx_res = await backends.dnsx_resolve(list(hosts)) if use_dnsx else None
            if dnsx_res is not None:
                log(f"[+] resolution via dnsx backend ({len(dnsx_res)} answered)")
                for name, h in hosts.items():
                    rec = dnsx_res.get(name)
                    if rec:
                        h.ips = rec["a"] + rec["aaaa"]
                        h.cname = rec["cname"]
                        _mark_wildcard(h)
            else:
                async def do_resolve(h):
                    h.ips, h.cname = await resolve_full(h.subdomain, ns)
                    _mark_wildcard(h)
                    return h
                await _gather_with_progress((do_resolve(h) for h in hosts.values()),
                                            "resolving", use_prog)
            log(f"[+] {sum(1 for h in hosts.values() if h.ips and not h.wildcard)} "
                f"resolving (non-wildcard) hosts")

            # ---- Dangling-CNAME takeover leads ----
            # A CNAME whose target doesn't resolve has no A record, so Phase 4
            # filters the host out (`h.ips` gate) and the HTTP-body signature
            # check can never run — this is the only place the classic takeover
            # case is visible. DNS-only, same touch tier as the resolution above.
            dangling = [h for h in hosts.values()
                        if h.cname and not h.ips and not h.wildcard]
            if dangling:
                statuses = await asyncio.gather(
                    *(cname_target_status(h.cname, ns) for h in dangling))
                for h, status in zip(dangling, statuses):
                    mark_dangling_cname(h, status)
                n_dangling = sum(1 for h in dangling if h.takeover)
                if n_dangling:
                    log(f"[!] {n_dangling} dangling CNAME(s) — subdomain-takeover "
                        f"candidate(s) with a non-existent target")

        # ---- Phase 3: enrichment on UNIQUE IPs ----
        ip_to_hosts = defaultdict(list)
        for h in hosts.values():
            if not h.wildcard:
                for ip in h.ips:
                    ip_to_hosts[ip].append(h)
        unique_ips = list(ip_to_hosts)
        if unique_ips:
            ports_src = "shodan" if shodan_key else "internetdb"
            # IPinfo's /json endpoint works keylessly (lower, unauthenticated
            # rate limit) — always attempt it rather than skipping ASN/org/
            # rDNS enrichment outright just because no token is configured.
            layers = ["ports/CVE:" + ports_src, "ipinfo" + ("" if ipinfo_token else " (keyless)")]
            enrich_sem = asyncio.Semaphore(args.concurrency)

            async def enrich_ip(ip):
                async with enrich_sem:
                    ports_data = (await enrich_shodan_host(client, ip, shodan_key, shodan_limiter)
                                  if shodan_key else await enrich_internetdb(client, ip))
                    info = await enrich_ipinfo(client, ip, ipinfo_token)
                return ip, ports_data, info
            results = await _gather_with_progress(
                (enrich_ip(ip) for ip in unique_ips),
                f"enriching {len(unique_ips)} unique IPs ({', '.join(layers)})", use_prog)
            for ip, ports_data, info in results:
                for h in ip_to_hosts[ip]:
                    apply_ports(h, ports_data, ports_src)
                    apply_ipinfo(h, info, ip)

        # ---- Phase 4: active probe / port scan / favicon ----
        certs = []
        if not args.passive_only:
            port_sem = asyncio.Semaphore(300)
            active_hosts = [h for h in hosts.values() if h.ips and not h.wildcard]

            # port scan backend: naabu > pure-python tcp_scan
            naabu_ok = args.active_ports and not args.no_pd and backends.have("naabu")

            # HTTP probe backend: PD httpx (batch, tech fingerprint) > per-host probe
            httpx_data = None
            if not args.no_pd:
                httpx_data = await backends.httpx_probe([h.subdomain for h in active_hosts])
            if httpx_data is not None:
                log(f"[+] HTTP probe via httpx backend ({len(httpx_data)} responded)")

            async def do_active(h):
                if args.active_ports:
                    if naabu_ok:
                        np = await backends.naabu_scan(h.ips[0], args.ports)
                        if np:
                            h.ports = sorted(set(h.ports) | set(np))
                    else:
                        await tcp_scan(h, args.ports, port_sem)
                if httpx_data is not None:
                    d = httpx_data.get(h.subdomain)
                    if d:
                        h.http_status = d["status"]
                        h.http_title = d["title"]
                        h.server = d["server"]
                        h.tech = d.get("tech", [])
                        h.scheme = d["scheme"]
                        h.final_url = d["final_url"]
                        if d.get("favicon") not in (None, ""):
                            try:
                                h.favicon_hash = int(d["favicon"])
                            except Exception:
                                pass
                    if h.cname:                          # takeover still needs body match
                        await takeover_check_host(probe_client, h)
                else:
                    await http_probe(probe_client, h)
                    if h.http_status and h.scheme and h.favicon_hash is None:
                        h.favicon_hash = await favicon_hash(probe_client, f"{h.scheme}://{h.subdomain}")
                return h
            await _gather_with_progress((do_active(h) for h in active_hosts),
                                        "probing", use_prog)

            # ---- Tech-stack confirmation: does the live probe corroborate
            # Shodan/InternetDB's (possibly stale) reported software? ----
            for h in active_hosts:
                h.tech_confirmed = confirm_tech_stack(h)
            n_confirmed = sum(1 for h in active_hosts if h.tech_confirmed is True)
            n_unconfirmed = sum(1 for h in active_hosts if h.tech_confirmed is False)
            if n_confirmed or n_unconfirmed:
                log(f"[+] tech-stack confirmation: {n_confirmed} host(s) corroborated live, "
                    f"{n_unconfirmed} unconfirmed (Shodan/InternetDB banner only — verify before triaging)")

            # ---- TLS certificates on live hosts ----
            # The cert a host actually serves — which CT logs and Shodan cannot
            # give us: names that never reached a log, and the mail/admin TLS
            # ports nobody submits to CT. Read without verification (see
            # tlsinfo) because expired/self-signed/mismatched certs are exactly
            # the ones worth reporting. Also the input for the SAN wire-back.
            if tlsinfo.HAVE_CRYPTO:
                targets = []
                for h in active_hosts:
                    open_tls = [p for p in (h.ports or []) if p in TLS_PORTS]
                    for port in (open_tls or [443])[:4]:      # cap per host
                        targets.append((h.subdomain, port))
                cert_sem = asyncio.Semaphore(args.concurrency)

                async def read_cert(name, port):
                    async with cert_sem:
                        c = await fetch_cert(name, port)
                    return {"host": name, "port": port, **c} if c else None

                got = await _gather_with_progress(
                    (read_cert(n, p) for n, p in targets),
                    f"reading TLS certs ({len(targets)} endpoint(s))", use_prog)
                certs = [c for c in got if c]
                if certs:
                    n_bad = sum(1 for c in certs if c["expired"] or c["self_signed"])
                    log(f"[+] TLS certs: {len(certs)} read"
                        + (f" ({n_bad} expired or self-signed)" if n_bad else ""))
            else:
                log("[i] TLS cert inspection: cryptography not installed — skipping "
                    "(pip install 'lrecon[tls]')")

        # ---- Cloudflare origin discovery ----
        cf = {"detected": False, "fronted": [], "candidates": {}}
        cf_nets = []
        if not args.no_cf_origin and not args.passive_only:
            cf_nets = await load_cf_ranges(client)
            cf = await cloudflare_origin_analysis(
                client, probe_client, domains, hosts, keys, cf_nets,
                active=not args.passive_only, resolver_ns=ns)
            if cf["detected"]:
                conf = sum(1 for v in cf["candidates"].values() if v["confirmed"])
                log(f"[+] Cloudflare detected on {len(cf['fronted'])} host(s) — "
                    f"{len(cf['candidates'])} origin candidate(s), {conf} confirmed")

        # ---- Favicon pivot (shodan) — find shadow assets sharing favicon ----
        favicon_pivots = {}
        if shodan_key and not args.passive_only:
            if not cf_nets:
                cf_nets = await load_cf_ranges(client)
            hashes = {h.favicon_hash for h in hosts.values() if h.favicon_hash}
            for fh in hashes:
                extra = await shodan_favicon_pivot(client, fh, shodan_key, cf_nets)
                if extra:
                    favicon_pivots[fh] = sorted(set(extra))

        # ---- rDNS wire-back: add in-scope PTR names as hosts ----
        for h in list(hosts.values()):
            if h.rdns and any(h.rdns.endswith(d) for d in domains) and h.rdns not in hosts:
                nh = Host(subdomain=h.rdns, source={"rdns"})
                if not args.passive_only:
                    nh.ips, nh.cname = await resolve_full(h.rdns, ns)
                hosts[h.rdns] = nh

        # ---- TLS SAN wire-back: add in-scope names found on live certs ----
        # Same shape as the rDNS wire-back above. in_scope_cert_names() drops
        # wildcards (not resolvable hosts) and anything outside scope — a shared
        # or CDN cert routinely carries other tenants' domains, which are not the
        # client's assets and must never enter the report.
        san_added = 0
        for cert in certs:
            for name in in_scope_cert_names(cert, domains):
                if name in hosts:
                    continue
                nh = Host(subdomain=name, source={"tls-san"})
                if not args.passive_only:
                    nh.ips, nh.cname = await resolve_full(name, ns)
                hosts[name] = nh
                san_added += 1
        if san_added:
            log(f"[+] tls-san: {san_added} new in-scope host(s) from certificate SANs")

        # ---- ASN / netblock expansion (opt-in) ----
        asn_info = {}
        if args.asn_expand and not args.passive_only:
            asns = {h.asn for h in hosts.values() if h.asn}
            for asn in asns:
                prefixes = await ripestat_prefixes(client, asn)
                asn_info[asn] = prefixes
                if prefixes:
                    swept = await reverse_dns_sweep(prefixes, ns, cap=args.asn_cap)
                    added = 0
                    for ip, host in swept.items():
                        if any(host.endswith(d) for d in domains) and host not in hosts:
                            hosts[host] = Host(subdomain=host, ips=[ip], source={"asn-rdns"})
                            added += 1
                    log(f"[+] {asn}: {len(prefixes)} prefixes, PTR-swept -> {added} new in-scope hosts")

        # ---- Intel phase: email posture, github, buckets, breach ----
        email = {}
        if not args.passive_only:
            for d in domains:
                email[d] = await email_security(d, ns)
                g = email[d].get("grade")
                if g:
                    log(f"[+] email {d}: {g} ({len(email[d].get('issues', []))} issue(s))")

        # ---- DNS records + mail infrastructure ----
        # Raw apex DNS snapshot (A/AAAA/MX/NS/SOA) for the report's DNS
        # section, plus MX-host enrichment to identify managed vs self-hosted
        # mail infra. Same touch tier as email_security() above (DNS query
        # against the domain's own authoritative nameservers), so gated the
        # same way, not alongside the keyless RDAP/WHOIS lookup earlier.
        dns_records = {}
        mail_infra = {}
        if not args.passive_only:
            for d in domains:
                dns_records[d] = await dns_lookup(d, ns)
                mx = dns_records[d].get("mx") or []
                if mx:
                    entries = await mail_infra_lookup(client, mx, ipinfo_token, ns)
                    mail_infra[d] = entries
                    providers = sorted({e["provider"] for e in entries if e["provider"]})
                    unmanaged = [e["host"] for e in entries if not e["provider"]]
                    if providers and not unmanaged:
                        log(f"[+] mail infra {d}: {', '.join(providers)}")
                    elif providers:
                        log(f"[+] mail infra {d}: {', '.join(providers)} + "
                            f"{len(unmanaged)} unrecognized host(s) — review")
                    else:
                        log(f"[!] mail infra {d}: no managed provider recognized — possible self-hosted MTA")

        gh_limiter = RateLimiter(per_second=0.2)              # code search ~10/min; shared below
        github_findings = []
        if keys.get("github"):
            for d in domains:
                github_findings += await github_dork(client, d, keys["github"], gh_limiter)
            if github_findings:
                log(f"[+] github: {len(github_findings)} code hit(s) referencing scope")

        buckets = []
        if args.buckets:
            kws = set()
            for d in domains:
                kws.add(d.split(".")[0])
            if args.bucket_keywords:
                kws |= set(args.bucket_keywords.split(","))
            buckets = await bucket_enum(client, kws)
            pub = sum(1 for b in buckets if b["public"])
            log(f"[+] buckets: {len(buckets)} exist ({pub} public-listable)")

        # ---- Search-engine dorking (opt-in --dork; needs Google CSE key+cx) ----
        # Explicit flag even with a key configured — the 100/day free quota is
        # tight enough (7 dork categories per domain) that it must not run
        # silently just because a key happens to be set. Allowed under
        # --passive-only: this only queries Google's own API, never the
        # target directly (same tier as bucket_enum and the People OSINT
        # sources, none of which are passive-only-gated either).
        dorks = []
        if args.dork:
            providers = configured_dork_providers(keys, getattr(args, "dork_provider", "auto"))
            if providers:
                dork_limiter = RateLimiter(per_second=1.0)
                dorks, used = await _run_dorks(client, domains, providers, keys, dork_limiter)
                if dorks:
                    n_cat = len({d["category"] for d in dorks})
                    log(f"[+] {'/'.join(used)} dork: {len(dorks)} hit(s) across "
                        f"{n_cat} categor{'y' if n_cat == 1 else 'ies'}")
            elif getattr(args, "dork_provider", "auto") not in (None, "auto"):
                log(f"[!] --dork set but --dork-provider {args.dork_provider} not configured — skipping")
            else:
                log("[!] --dork set but no search backend configured "
                    "(google-cse / brave / vertex) — skipping")

        breach = {}
        for d in domains:
            b = await hibp_breaches(client, d)
            if b:
                breach[d] = b
        if breach:
            log(f"[+] breach: {sum(len(v) for v in breach.values())} known breach(es) for scope")

        # ---- OSINT user enumeration (opt-in: runs if hunter/rocketreach/github
        # keys are configured, same "presence of a key = opt-in" convention as
        # the rest of lrecon's keyed enrichment) ----
        people = []
        if keys.get("hunter") or keys.get("rocketreach") or keys.get("github"):
            for d in domains:
                people += await enumerate_people(client, d, keys, gh_limiter, args.company_name)
            if people:
                log(f"[+] people-enum: {len(people)} company-affiliated email(s) discovered")

            if args.verify_emails and people and not args.passive_only:
                for d in domains:
                    d_people = [p for p in people if p.email.endswith(f"@{d}")]
                    if not d_people:
                        continue
                    statuses = await verify_emails(d, [p.email for p in d_people], ns)
                    for p in d_people:
                        p.smtp_status = statuses.get(p.email)
                n_valid = sum(1 for p in people if p.smtp_status == "valid")
                n_catchall = sum(1 for p in people if p.smtp_status == "catch-all")
                n_invalid = sum(1 for p in people if p.smtp_status == "invalid")
                log(f"[+] email verify: {n_valid} valid, {n_catchall} catch-all/inconclusive, "
                    f"{n_invalid} invalid")

        # ---- NVD CVE enrichment (opt-in; cached) ----
        # Resolves CPEs to CVEs, and also enriches bare Shodan/InternetDB CVE IDs
        # (h.vulns) with CVSS/vector/description, so entry-point severity ranking
        # and DoS filtering (see intel.summarize_entry_points) apply to both.
        if args.nvd and not args.passive_only:
            nvd_cache, nvd_id_cache = {}, {}
            nvd_limiter = RateLimiter(per_second=0.16)        # ~5 req / 30s keyless
            nvd_hosts = [h for h in hosts.values() if h.cpes or h.vulns]
            cap = args.nvd_max_cves                           # per-host cap on bare vuln IDs resolved

            # Resolve each unique bare CVE ID once, up front. Hosts sharing an IP
            # (CDN/vhost) get an identical h.vulns list from apply_ports(), so
            # without this every host's concurrent do_nvd() below would miss the
            # cache at the same time and each fire its own duplicate, serialized
            # lookup for the same shared CVE ID against the 0.16 req/s limiter.
            unique_vuln_ids = sorted({vid for h in nvd_hosts for vid in h.vulns[:cap]})
            if unique_vuln_ids:
                await _gather_with_progress(
                    (nvd_lookup_by_id(client, vid, nvd_id_cache, nvd_limiter)
                     for vid in unique_vuln_ids),
                    f"NVD lookup ({len(unique_vuln_ids)} known CVE ID(s))", use_prog)

            async def do_nvd(h):
                seen = {}
                for cpe in h.cpes[:5]:
                    for cve in await nvd_lookup(client, cpe, nvd_cache, nvd_limiter):
                        if cve["id"]:
                            seen[cve["id"]] = cve
                for vid in h.vulns[:cap]:
                    if vid not in seen:
                        enriched = await nvd_lookup_by_id(client, vid, nvd_id_cache, nvd_limiter)
                        if enriched:
                            seen[vid] = enriched
                h.nvd_cves = sorted(seen.values(), key=lambda c: -(c["cvss"] or 0))
            if nvd_hosts:
                await _gather_with_progress((do_nvd(h) for h in nvd_hosts),
                                            f"NVD lookup ({len(nvd_hosts)} hosts)", use_prog)

            # ---- Public PoC lookup for the CVEs NVD just resolved (dedup once) ----
            poc_cache = {}
            poc_limiter = RateLimiter(per_second=5.0)
            unique_cve_ids = sorted({c["id"] for h in nvd_hosts for c in (h.nvd_cves or []) if c.get("id")})
            if unique_cve_ids:
                poc_results = await _gather_with_progress(
                    (poc_lookup(client, cid, poc_cache, poc_limiter) for cid in unique_cve_ids),
                    f"PoC lookup ({len(unique_cve_ids)} CVE(s))", use_prog)
                n_with_poc = sum(1 for v in poc_cache.values() if v)
                n_failed = sum(1 for r in poc_results if r is None)
                if n_with_poc:
                    log(f"[+] public PoC found for {n_with_poc}/{len(unique_cve_ids)} resolved CVE(s)")
                if n_failed:
                    log(f"[!] PoC lookup failed for {n_failed}/{len(unique_cve_ids)} CVE(s) after "
                        f"retries — treated as unknown, not confirmed absent")
                for h in nvd_hosts:
                    for c in (h.nvd_cves or []):
                        if c.get("id") in poc_cache:
                            c["poc"] = poc_cache[c["id"]]

        # ---- nuclei templated vuln scan (opt-in; ProjectDiscovery backend) ----
        nuclei = []
        if args.nuclei and not args.passive_only and not args.no_pd:
            live_urls = [h.final_url or f"{h.scheme}://{h.subdomain}"
                         for h in hosts.values()
                         if h.http_status and not h.wildcard]
            if live_urls and backends.have("nuclei"):
                log(f"[+] nuclei scanning {len(live_urls)} live host(s)"
                    + (f" (severity>={args.nuclei_severity})" if args.nuclei_severity else ""))
                res = await backends.nuclei_scan(live_urls, severity=args.nuclei_severity)
                nuclei = res or []
                log(f"[+] nuclei: {len(nuclei)} finding(s)")
            elif not backends.have("nuclei"):
                log("[!] --nuclei set but nuclei binary not on PATH — skipping")

    host_list = sorted(hosts.values(), key=lambda h: h.subdomain)

    # ---- Passive auth-surface mapping (OIDC/SSO discovery) ----
    # One HTTPS GET of each live host's public OIDC discovery document —
    # standards-defined metadata only, no login/credential probing. Touches
    # target-owned hosts (same as the HTTP probe), so it's gated on
    # not-passive-only and uses probe_client (self-signed certs common on
    # auth endpoints). Feeds both entry_points and the dossier.
    auth_surfaces = []
    if not args.passive_only:
        live = [h for h in host_list if h.http_status and not h.wildcard]
        results = await asyncio.gather(*[auth_surface(probe_client, h.subdomain) for h in live])
        auth_surfaces = [a for a in results if a]
        if auth_surfaces:
            idps = ", ".join(sorted({a.get("idp") or "unknown" for a in auth_surfaces}))
            log(f"[+] auth-surface: {len(auth_surfaces)} host(s) expose OIDC/SSO discovery ({idps})")

    # ---- Entry-point summary (red-team signal: what to chase first) ----
    entry_points = summarize_entry_points(host_list, cf, buckets, breach, github_findings,
                                          nuclei, dorks, auth_surfaces, whois=whois)
    if entry_points:
        log(f"[!] {len(entry_points)} potential entry point(s) identified:")
        for ep in entry_points:
            log(f"    [ENTRY POINT] [{ep['severity'].upper()}] {ep['target']} — {ep['summary']}")
    else:
        log("[+] no high-confidence entry points identified this pass")

    # ---- Diff vs previous run ----
    diff = {}
    if args.diff:
        diff = diff_snapshot(load_prev_snapshot(domains), host_list)
    save_snapshot(domains, host_list)

    return {"hosts": host_list, "per_source": dict(per_source), "cf": cf,
            "email": email, "github": github_findings, "buckets": buckets,
            "breach": breach, "asn": asn_info, "favicon_pivots": favicon_pivots,
            "nuclei": nuclei, "diff": diff, "entry_points": entry_points, "people": people,
            "whois": whois, "dorks": dorks, "dns": dns_records, "mail_infra": mail_infra,
            "vt": vt_intel, "auth_surface": auth_surfaces, "certs": certs}


