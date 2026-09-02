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
from .kev import load_kev, epss_scores

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


def _scrub(text: str, keys: dict) -> str:
    """Redact every configured API key from a string before it is logged. Some
    services take the key in the query string (Shodan `?key=`, Hunter/RocketReach
    `?api_key=`), and an httpx transport error stringifies the request URL — so a
    transient network failure could otherwise print a live key into the run log
    and any terminal capture. Also covers a key echoed in a provider error body."""
    out = text
    for v in (keys or {}).values():
        if v and isinstance(v, str) and len(v) >= 6:
            out = out.replace(v, "***")
    return out


async def verify_keys(client, keys: dict, dorking: bool = False) -> None:
    """
    On-boot API key verification — one cheap, non-quota-consuming call per
    configured key (account-info endpoints where available, not the actual
    feature endpoints), so a bad/expired key surfaces immediately as
    "Invalid" instead of silently degrading whatever phase uses it later.
    Nulls out rejected keys in keys (in place) so the rest of the pipeline
    automatically falls back to keyless/skips that service, same as the
    prior Shodan-only check this replaces.

    `dorking` gates the one service with no free account endpoint (Brave), where
    "verify the key" and "spend quota" are the same request — see below.
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
            log(f"[!] Shodan API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

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
            log(f"[!] IPinfo API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

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
            log(f"[!] GitHub API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

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
            log(f"[!] Hunter.io API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

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
            log(f"[!] RocketReach API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

    # Brave has no free account endpoint — the only way to validate a key is to
    # spend a search from the monthly quota. So this runs *only* when dorking is
    # actually requested: charging every ordinary scan one search out of 2k/mo,
    # to validate a key that run was never going to use, would eat the opt-in
    # dorking budget (and can 429 it) for no benefit.
    if keys.get("brave") and dorking:
        try:
            r = await client.get("https://api.search.brave.com/res/v1/web/search",
                                params={"q": "lrecon", "count": 1},
                                headers={"X-Subscription-Token": keys["brave"],
                                         "Accept": "application/json"}, timeout=15)
            if r.status_code == 200:
                log("[+] Brave Search API: Ready")
            elif r.status_code in (401, 403):
                log("[!] Brave Search API: Invalid — dorking via Brave disabled")
                keys["brave"] = None
            elif r.status_code == 429:
                log("[!] Brave Search API: rate limited at startup — proceeding anyway")
            else:
                log(f"[!] Brave Search API: unexpected response (HTTP {r.status_code}) "
                    f"— proceeding anyway")
        except Exception as e:
            log(f"[!] Brave Search API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

    if keys.get("vt"):
        try:
            # /users/{key} is the documented account endpoint and costs no
            # lookup quota, which matters on a tier capped at 4 req/min.
            r = await client.get(f"https://www.virustotal.com/api/v3/users/{keys['vt']}",
                                headers={"x-apikey": keys["vt"]}, timeout=15)
            if r.status_code == 200:
                log("[+] VirusTotal API: Ready")
            elif r.status_code in (401, 403):
                log("[!] VirusTotal API: Invalid — --vt domain intelligence disabled")
                keys["vt"] = None
            else:
                log(f"[!] VirusTotal API: unexpected response (HTTP {r.status_code}) "
                    f"— proceeding anyway")
        except Exception as e:
            log(f"[!] VirusTotal API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

    if keys.get("otx"):
        try:
            r = await client.get("https://otx.alienvault.com/api/v1/user/me",
                                headers={"X-OTX-API-KEY": keys["otx"]}, timeout=15)
            if r.status_code == 200:
                log("[+] OTX API: Ready")
            elif r.status_code in (401, 403):
                log("[!] OTX API: Invalid — passive DNS via OTX disabled")
                keys["otx"] = None
            else:
                log(f"[!] OTX API: unexpected response (HTTP {r.status_code}) "
                    f"— proceeding anyway")
        except Exception as e:
            log(f"[!] OTX API: check failed ({_scrub(str(e), keys)}) — proceeding anyway")

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
    headers = {"User-Agent": USER_AGENT}
    shodan_limiter = RateLimiter(per_second=1.0)

    # `client` verifies certs — used for calls to trusted third-party APIs (Shodan,
    # IPinfo, GitHub, HIBP, NVD, crt.sh, etc.), several of which carry API keys/tokens.
    # `probe_client` skips verification — needed when touching engagement targets
    # directly (self-signed / mismatched certs are common there).
    async with httpx.AsyncClient(limits=limits, headers=headers, verify=True,
                                follow_redirects=False) as client, \
              httpx.AsyncClient(limits=limits, headers=headers, verify=False,
                                follow_redirects=False) as probe_client:

        await verify_keys(client, keys, dorking=bool(getattr(args, "dork", False)))
        shodan_key = keys.get("shodan")           # re-sync: verify_keys() may have nulled either
        ipinfo_token = keys.get("ipinfo")

        # ---- Phase 1: passive enum (with source attribution) ----
        # Skip entirely on an IP-only run (no domains) — the passive sources are
        # all domain-keyed (crt.sh, OTX, wayback…) and have nothing to query.
        if domains:
            host_sources, per_source, failed_sources = await passive_enum(
                client, domains, keys, no_pd=args.no_pd)
        else:
            host_sources, per_source, failed_sources = {}, {}, {}
        hosts = {n: Host(subdomain=n, source=set(srcs)) for n, srcs in host_sources.items()}
        breakdown = "  ".join(f"{s}={per_source[s]}" for s in sorted(per_source)) or "none"
        log(f"[+] {len(hosts)} unique subdomains  |  by source: {breakdown}")
        # `otx=0` from a blocked source and `otx=0` from a clean domain look
        # identical in the line above, and only one of them is about the target.
        for src in sorted(failed_sources):
            log(f"[!] source '{src}' contributed nothing because it failed, not because "
                f"the domain(s) had no hosts there: {failed_sources[src]}")
        if per_source.get("crtsh", 0) == 0:
            log("[!] crt.sh returned 0 — its frontend 502s/times out intermittently under "
                "load; both query forms were retried (see the crt.sh lines above for the "
                "per-attempt statuses). Other CT sources (certspotter/OTX) cover this; "
                "--no-pd skips the direct-Postgres tier if it is being slow.")

        # ---- Active brute-force / permutation (opt-in --brute, ROE-gated) ----
        # Candidates are queued into `hosts` here, before Phase 2, so they ride
        # the existing resolver: detect_wildcard + _mark_wildcard filter the
        # phantoms a wildcard domain would otherwise inflate them into, and the
        # dnsx backend resolves the whole enlarged set in one batch. Only names
        # that actually resolve survive into the report.
        if getattr(args, "brute", False) and not args.passive_only and domains:
            words = getattr(args, "brute_words", [])
            cands = brute_candidates(domains, set(hosts), words,
                                     cap=getattr(args, "brute_cap", 5000))
            wl_set = {f"{w.lower()}.{d.lower()}" for w in words for d in domains}
            for name in cands:
                hosts[name] = Host(subdomain=name,
                                   source={"brute" if name in wl_set else "permutation"})
            n_perm = sum(1 for c in cands if c not in wl_set)
            log(f"[!] --brute: {len(cands)} candidate name(s) queued "
                f"({n_perm} from permutation) — active DNS at the target's NS, confirm SOW")

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
                # Independent per domain; the shared vt_limiter still enforces
                # VT's rate ceiling at each request, so gathering only overlaps
                # the waiting, never exceeds the limit.
                async def _vt(d):
                    return d, await vt_domain_intel(client, d, keys["vt"], vt_limiter)
                for d, info in await _gather_with_progress(
                        (_vt(d) for d in domains), "VirusTotal", use_prog):
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
        # vt_intel is fully populated above, so each domain's WHOIS (which may
        # fall back to VT's cached text) is independent — gather them.
        async def _whois(d):
            return d, await whois_lookup(client, d, vt_intel.get(d, {}).get("whois"))
        for d, w in await _gather_with_progress(
                (_whois(d) for d in domains), "WHOIS", use_prog):
            whois[d] = w
            if w.get("expires") and domain_expiring_soon(w["expires"]):
                log(f"[!] {d}: domain registration expires {w['expires']} — flag to client")

        # ---- Phase 2: resolution + wildcard filter ----
        if not args.passive_only:
            wildcard_ips = {d: await detect_wildcard(d, ns) for d in domains}

            def _mark_wildcard(h):
                root = next((d for d in domains if name_in_scope(h.subdomain, d)), None)
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
                # Bound the DNS fan-out: resolve_full fires 3 queries per host,
                # and a multi-thousand-host scope would otherwise open that many
                # sockets at once and exhaust file descriptors. Mirrors enrich_sem.
                resolve_sem = asyncio.Semaphore(args.concurrency)

                async def do_resolve(h):
                    async with resolve_sem:
                        h.ips, h.cname, h.nxdomain = await resolve_full(h.subdomain, ns)
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
                for h, (status, closest_zone) in zip(dangling, statuses):
                    mark_dangling_cname(h, status, closest_zone)
                n_dangling = sum(1 for h in dangling if h.takeover)
                if n_dangling:
                    log(f"[!] {n_dangling} dangling CNAME(s) — subdomain-takeover "
                        f"candidate(s) with a non-existent target")

            # ---- Dangling-NS (zone) takeover leads ----
            # A delegated nameserver whose own name no longer resolves means
            # whoever can register that NS name controls this zone's DNS — a
            # takeover a level above the per-record CNAME case. Bounded to the
            # seed domains (their apex NS RRset), where a broken delegation is
            # most impactful; DNS-only, same touch tier as resolution.
            n_ns = 0
            for d in domains:
                seed = hosts.get(d)
                if not seed:
                    continue
                for nsname in await ns_records(d, ns):
                    _ips, _cn, ns_nx = await resolve_full(nsname, ns)
                    if ns_nx:
                        seed.ns_takeover = (
                            f"Delegated nameserver {nsname} does not exist (NXDOMAIN); "
                            f"if its name is registrable, an attacker who registers it "
                            f"controls this zone's DNS — verify claimability")
                        n_ns += 1
                        break
            if n_ns:
                log(f"[!] {n_ns} domain(s) with a dangling NS delegation — potential "
                    f"zone takeover")

        # ---- Seed operator-supplied IP / CIDR targets ----
        # These skip Phase 1 (nothing to enumerate) and Phase 2 (no DNS on an IP
        # literal) and join here with their address already attached, so the
        # IP-keyed enrichment below and the Phase 4 active probe run on them
        # unchanged. Added outside the --passive-only guard so they're enriched
        # (Shodan/InternetDB + IPinfo, all passive API lookups) just like any
        # IP a domain resolved to.
        n_ip_seed = 0
        for ip in getattr(args, "ip_targets", []):
            if ip not in hosts:
                hosts[ip] = Host(subdomain=ip, ips=[ip], source={"ip-seed"})
                n_ip_seed += 1
        if n_ip_seed:
            log(f"[+] {n_ip_seed} IP target(s) added directly for enrichment/probe")

        # ---- Phase 3: enrichment on UNIQUE IPs ----
        ip_to_hosts = defaultdict(list)
        for h in hosts.values():
            if not h.wildcard:
                for ip in h.ips:
                    ip_to_hosts[ip].append(h)
        unique_ips = list(ip_to_hosts)
        if unique_ips:
            # Shodan's host API is a hard 1 req/s, so per-IP Shodan on a large
            # set crawls (~1000 IPs = ~17 min). InternetDB is Shodan's own free
            # dataset (ports/CPEs/CVEs) with no per-second wall, and ASN/org come
            # from ipinfo anyway — so above --shodan-max-ips, use InternetDB.
            use_shodan = use_shodan_ports(shodan_key, len(unique_ips), args.shodan_max_ips)
            if shodan_key and not use_shodan:
                log(f"[i] {len(unique_ips)} unique IPs exceeds Shodan's 1 req/s budget "
                    f"(~{len(unique_ips)}s) — using InternetDB (Shodan's free dataset) for "
                    f"ports/CVEs; raise --shodan-max-ips to force per-IP Shodan")
            ports_src = "shodan" if use_shodan else "internetdb"
            # IPinfo's /json endpoint works keylessly (lower, unauthenticated
            # rate limit) — always attempt it rather than skipping ASN/org/
            # rDNS enrichment outright just because no token is configured. With
            # a token, one /batch call replaces a per-IP GET each.
            ipinfo_map = (await enrich_ipinfo_batch(client, unique_ips, ipinfo_token)
                          if ipinfo_token else None)
            layers = ["ports/CVE:" + ports_src,
                      "ipinfo" + (" (batch)" if ipinfo_token else " (keyless)")]
            enrich_sem = asyncio.Semaphore(args.concurrency)

            async def enrich_ip(ip):
                async with enrich_sem:
                    if use_shodan:
                        ports_coro = enrich_shodan_host(client, ip, shodan_key, shodan_limiter)
                    else:
                        ports_coro = enrich_internetdb(client, ip)
                    if ipinfo_map is not None:
                        ports_data, info = await ports_coro, ipinfo_map.get(ip, {})
                    else:
                        # Keyless ipinfo: overlap the per-IP GET with the ports fetch.
                        ports_data, info = await asyncio.gather(
                            ports_coro, enrich_ipinfo(client, ip, ipinfo_token))
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
            api_sem = asyncio.Semaphore(30)      # bounds --api-scan HTTP fan-out
            banner_sem = asyncio.Semaphore(100)  # bounds banner-grab connections
            active_hosts = [h for h in hosts.values() if h.ips and not h.wildcard]

            # port scan backend: naabu > pure-python tcp_scan
            naabu_ok = args.active_ports and not args.no_pd and backends.have("naabu")

            async def _do_active(h, httpx_data):
                if args.active_ports:
                    if naabu_ok:
                        # Scan every resolved IP, not just the first — a
                        # round-robin/multi-homed host otherwise gets 1/N port
                        # coverage reported as if complete. naabu's -host takes a
                        # comma list; the union of open ports lands on h.ports.
                        np = await backends.naabu_scan(",".join(h.ips), args.ports)
                        if np:
                            h.ports = sorted(set(h.ports) | set(np))
                    else:
                        await tcp_scan(h, args.ports, port_sem)
                    # Banner-grab the open ports for service/version evidence
                    # (SSH ident, TLS cert, greeting). Same ROE tier as the scan
                    # that just found them; --no-banners suppresses.
                    if h.ports and not getattr(args, "no_banners", False):
                        await grab_banners(h, h.ports, banner_sem)
                    # Probe any open non-standard web port (8080/8443/...) the
                    # scan found — http_probe only tries 80/443, so these live
                    # services (often admin panels) would otherwise be a bare
                    # port number in the report. Same ROE tier as the scan.
                    await probe_web_ports(probe_client, h)
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
                # API-doc + same-origin JS secret discovery on live hosts (opt-in).
                if getattr(args, "api_scan", False) and h.http_status and h.scheme:
                    await discover_endpoints(probe_client, h, api_sem,
                                             js_max=getattr(args, "js_max", 8))
                return h

            # One probe pass over an arbitrary host list — the seed set now, the
            # favicon-expansion set later — so both share exactly the same
            # probe/port-scan/favicon path rather than a second copy of it. The
            # httpx batch (tech fingerprint) is per-list, since the expansion
            # hosts aren't known when the seed set is probed.
            async def probe_hosts(host_list, desc="probing"):
                if not host_list:
                    return
                httpx_data = None
                if not args.no_pd:
                    httpx_data = await backends.httpx_probe([h.subdomain for h in host_list])
                    if httpx_data is not None:
                        log(f"[+] HTTP probe via httpx backend ({len(httpx_data)} responded)")
                await _gather_with_progress((_do_active(h, httpx_data) for h in host_list),
                                            desc, use_prog)

            await probe_hosts(active_hosts)

            if args.active_ports and not getattr(args, "no_banners", False):
                n_ban = sum(len(h.banners) for h in active_hosts)
                if n_ban:
                    log(f"[+] banners: {n_ban} service banner(s) grabbed on open ports")

            if getattr(args, "api_scan", False):
                n_docs = sum(1 for h in active_hosts for e in h.endpoints
                             if e.get("source") in ("api-doc", "js-sourcemap"))
                n_sec = sum(len(h.js_secrets) for h in active_hosts)
                log(f"[+] api-scan: {n_docs} API-doc/sourcemap endpoint(s), {n_sec} secret "
                    f"lead(s) in JS bundles" + (" — verify per ROE" if n_sec else ""))

            # ---- Wayback stale-endpoint hunt (opt-in --wayback-paths) ----
            # Mine archived paths per in-scope host (keyless CDX), then
            # re-request them on live hosts now: a 200/401/403/500 on a path the
            # site served years ago is a forgotten admin panel or old app no
            # passive source surfaces. Active (touches the target), so gated and
            # bounded by --wayback-cap total requests.
            if getattr(args, "wayback_paths", False):
                mined = defaultdict(list)
                for d in domains:
                    for host, paths in (await wayback_paths(client, d)).items():
                        for p in paths:
                            if p not in mined[host]:
                                mined[host].append(p)
                budget = getattr(args, "wayback_cap", 400)
                wb_sem = asyncio.Semaphore(50)
                n_checked, wb_tasks = 0, []
                for h in active_hosts:
                    if n_checked >= budget:
                        break
                    slice_ = mined.get(h.subdomain, [])[: budget - n_checked]
                    if not slice_:
                        continue
                    n_checked += len(slice_)
                    wb_tasks.append(verify_wayback_paths(probe_client, h, slice_, wb_sem))
                if wb_tasks:
                    await asyncio.gather(*wb_tasks)
                    n_found = sum(len(h.endpoints) for h in active_hosts)
                    log(f"[+] wayback endpoints: re-verified {n_checked} archived path(s), "
                        f"{n_found} still responding (forgotten-app leads)")
                elif mined:
                    log("[i] wayback endpoints: archived paths found but no live host to "
                        "re-verify them against")

            # ---- GitHub Pages: is the lead actually claimable? ----
            # *.github.io is wildcarded, so a dead Pages target never NXDOMAINs
            # and the body signature is the only thing that fires — and it reads
            # the same for a free username as for a live account with no site.
            # One account lookup separates them; without it every stale Pages
            # record from a working org reads as a takeover.
            pages_hosts = [h for h in active_hosts
                           if h.takeover and github_pages_account(h.cname)]
            if pages_hosts:
                await asyncio.gather(*(resolve_github_pages_claimability(
                    probe_client, h, keys.get("github")) for h in pages_hosts))

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
                # cryptography is a base dependency now, so reaching here means
                # a broken install rather than a missing extra — most often a
                # distro cryptography whose native bits don't load (tlsinfo
                # catches the pyo3 panic that produces). Reinstalling is the fix;
                # naming an extra would send someone chasing the wrong thing.
                log("[!] TLS cert inspection: cryptography failed to import — skipping. "
                    "It is a required dependency, so this is a broken install: try "
                    "`pip install --force-reinstall cryptography`")

        # ---- Cloudflare origin discovery ----
        cf = {"detected": False, "fronted": [], "candidates": {}}
        cf_nets = []
        # Skip on a domainless (IP-only) scope: origin discovery is inherently
        # domain-based — it confirms a candidate with a cert-scope match against
        # `domains` and a spoofed `Host: domains[0]` header, both meaningless
        # (and the latter an IndexError) with no domains in scope.
        if not args.no_cf_origin and not args.passive_only and domains:
            cf_nets = await load_cf_ranges(client)
            cf = await cloudflare_origin_analysis(
                client, probe_client, domains, hosts, keys, cf_nets,
                active=not args.passive_only, resolver_ns=ns)
            if cf["detected"]:
                conf = sum(1 for v in cf["candidates"].values() if v["confirmed"])
                log(f"[+] Cloudflare detected on {len(cf['fronted'])} host(s) — "
                    f"{len(cf['candidates'])} origin candidate(s), {conf} confirmed")

        # ---- VirusTotal hosting history: who hosted each past IP? ----
        # Runs here rather than beside the VT fetch because the Cloudflare
        # ranges are only loaded above, and "was this address behind the CDN"
        # is the part of the history worth acting on.
        if vt_intel:
            # Per domain, not pooled: a shared IP that is live for one scoped
            # domain must not hide another domain's stale record.
            live_by_domain = {}
            for d in domains:
                live_by_domain[d] = {ip for h in hosts.values()
                                     if not h.wildcard and h.ips
                                     and (h.subdomain == d or h.subdomain.endswith("." + d))
                                     for ip in h.ips}
            n_hist_ips = await enrich_ip_history(client, vt_intel, ipinfo_token,
                                                 cf_nets, live_by_domain)
            if n_hist_ips:
                n_origin = sum(1 for v in vt_intel.values()
                               for r in (v.get("ip_history") or [])
                               if r.get("origin_candidate"))
                log(f"[+] VirusTotal hosting history: {n_hist_ips} historical IP(s) enriched"
                    + (f" — {n_origin} outside Cloudflare and no longer live "
                       f"(origin candidate(s) to verify)" if n_origin else ""))
                unknown = [d for d, v in vt_intel.items()
                           if v.get("origin_check") == "unknown"]
                if unknown:
                    log(f"[i] hosting history: origin-candidate check skipped for "
                        f"{', '.join(sorted(unknown))} — no live IPs to compare against, "
                        f"so whether the domain is CDN-fronted is unknown (not a clean result)")

        # ---- Favicon pivot (shodan) — find shadow assets sharing favicon ----
        # A custom favicon is a company fingerprint: hosts serving it are very
        # likely the same org's, even when their names look nothing like the
        # seed domains. That is the whole point, and also why a match on an
        # unrelated domain is only *evidence* of ownership, never proof — so
        # cross-domain hosts are reported with that evidence but not probed
        # unless the operator opts in with --favicon-expand (see below).
        #
        # Seed the pivot ONLY from the seed domains (and their www), never from
        # enumerated subdomains: a subdomain running GitLab, cPanel or Google
        # Workspace serves that vendor's stock favicon, and pivoting on it drags
        # in every unrelated host running the same software. A favicon is a
        # company fingerprint only when it is the company's — i.e. served by the
        # domains the operator actually named.
        favicon_pivots = {}
        if shodan_key and not args.passive_only:
            if not cf_nets:
                cf_nets = await load_cf_ranges(client)
            # Make sure each seed domain's own www is present and probed before
            # seeding the pivot. A site whose apex is blank and whose canonical
            # host is www serves its favicon only on www; if no passive source
            # enumerated www it is otherwise absent here, and the pivot would run
            # with no company favicon at all. Skip a www that doesn't resolve so
            # a domain without one contributes nothing.
            www_seeds = []
            for d in domains:
                w = f"www.{d}"
                if w in hosts:
                    continue
                nh = Host(subdomain=w, source={"seed-www"})
                nh.ips, nh.cname, nh.nxdomain = await resolve_full(w, ns)
                if not nh.ips:
                    continue
                hosts[w] = nh
                www_seeds.append(nh)
            if www_seeds:
                await probe_hosts(www_seeds, desc="probing seed www for favicon")

            fav_sources = seed_favicon_sources(hosts.values(), domains)
            # The searched icon itself, so a report reader can confirm each hash
            # is the org's logo. One fetch per hash (a handful), backend-agnostic.
            # Fetch on the scheme the seed host actually answered on — hardcoding
            # https makes an http-only host burn the full 10s timeout and render
            # no icon, stalling multi-domain scans.
            fav_images = {}
            for fh, srcs in fav_sources.items():
                seed_h = hosts.get(srcs[0])
                base = favicon_fetch_base(seed_h) if seed_h else f"https://{srcs[0]}"
                fav_images[fh] = await favicon_data_uri(probe_client, base)
            expand_hosts = {}
            for fh in fav_sources:
                meta = {"sources": sorted(fav_sources[fh]), "image": fav_images.get(fh)}
                res_fp = await shodan_favicon_pivot(client, fh, shodan_key, cf_nets,
                                                    limiter=shodan_limiter)
                if res_fp.get("skipped"):
                    favicon_pivots[fh] = {"skipped": res_fp["skipped"], **meta}
                    log(f"[i] favicon {fh}: {res_fp['skipped']:,} matches — too common to "
                        f"be a company marker, skipped")
                    continue
                matches = res_fp.get("matches") or []
                if not matches:
                    continue
                matches, expand = classify_favicon_matches(matches, domains, name_in_scope)
                expand_hosts.update({n: ip for n, ip in expand.items() if n not in expand_hosts})
                favicon_pivots[fh] = {"matches": matches, **meta}

            # --favicon-expand: pull the cross-domain matches into the active
            # pipeline. Off by default and loud when on, because a shared icon is
            # weak ownership evidence and this actively touches hosts outside the
            # seed domains — confirm they are in the SOW.
            new_favicon_hosts = [
                Host(subdomain=n, ips=[ip], source={"favicon"})
                for n, ip in sorted(expand_hosts.items()) if n not in hosts]
            if getattr(args, "favicon_expand", False) and new_favicon_hosts and not args.passive_only:
                log(f"[!] --favicon-expand: probing {len(new_favicon_hosts)} host(s) matched "
                    f"only by favicon — outside the seed domains; confirm they are in your SOW")
                for h in new_favicon_hosts:
                    hosts[h.subdomain] = h
                    h.source.add("favicon-expand")
                await probe_hosts(new_favicon_hosts, desc="probing favicon matches")
            elif new_favicon_hosts:
                log(f"[i] favicon pivot: {len(new_favicon_hosts)} cross-domain host(s) found "
                    f"— reported with evidence but not probed (pass --favicon-expand to probe, "
                    f"after confirming SOW)")

        # ---- rDNS wire-back: add in-scope PTR names as hosts ----
        for h in list(hosts.values()):
            if h.rdns and any(name_in_scope(h.rdns, d) for d in domains) and h.rdns not in hosts:
                nh = Host(subdomain=h.rdns, source={"rdns"})
                if not args.passive_only:
                    nh.ips, nh.cname, nh.nxdomain = await resolve_full(h.rdns, ns)
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
                    nh.ips, nh.cname, nh.nxdomain = await resolve_full(name, ns)
                hosts[name] = nh
                san_added += 1
        if san_added:
            log(f"[+] tls-san: {san_added} new in-scope host(s) from certificate SANs")

        # ---- ASN / netblock expansion (opt-in) ----
        asn_info = {}
        if args.asn_expand and not args.passive_only:
            asns = {h.asn for h in hosts.values() if h.asn}
            barren = []
            for asn in asns:
                prefixes = await ripestat_prefixes(client, asn)
                asn_info[asn] = prefixes
                if prefixes:
                    swept = await reverse_dns_sweep(prefixes, ns, cap=args.asn_cap)
                    added = 0
                    for ip, host in swept.items():
                        if any(name_in_scope(host, d) for d in domains) and host not in hosts:
                            hosts[host] = Host(subdomain=host, ips=[ip], source={"asn-rdns"})
                            added += 1
                    # An ASN that yielded nothing is the normal case and says
                    # nothing an operator can act on. One summary line records
                    # that the sweep ran; the per-ASN lines are kept for the
                    # ASNs that actually produced hosts.
                    if added:
                        log(f"[+] {asn}: {len(prefixes)} prefixes, PTR-swept -> "
                            f"{added} new in-scope hosts")
                    else:
                        barren.append(asn)
            if barren:
                log(f"[i] ASN expansion: {len(barren)} ASN(s) swept with no new in-scope "
                    f"hosts ({', '.join(sorted(barren)[:6])}"
                    + (f" +{len(barren) - 6} more" if len(barren) > 6 else "") + ")")

        # ---- Intel phase: email posture, github, buckets, breach ----
        email = {}
        if not args.passive_only:
            async def _email(d):
                return d, await email_security(d, ns, client)
            for d, e in await _gather_with_progress(
                    (_email(d) for d in domains), "email posture", use_prog):
                email[d] = e
                g = e.get("grade")
                if g:
                    log(f"[+] email {d}: {g} ({len(e.get('issues', []))} issue(s))")

        # ---- DNS records + mail infrastructure ----
        # Raw apex DNS snapshot (A/AAAA/MX/NS/SOA) for the report's DNS
        # section, plus MX-host enrichment to identify managed vs self-hosted
        # mail infra. Same touch tier as email_security() above (DNS query
        # against the domain's own authoritative nameservers), so gated the
        # same way, not alongside the keyless RDAP/WHOIS lookup earlier.
        dns_records = {}
        mail_infra = {}
        if not args.passive_only:
            # Each domain's DNS snapshot + its MX-infra lookup are independent;
            # do both inside one per-domain coroutine and gather across domains.
            async def _dns(d):
                rec = await dns_lookup(d, ns)
                mx = rec.get("mx") or []
                entries = await mail_infra_lookup(client, mx, ipinfo_token, ns) if mx else None
                return d, rec, entries
            for d, rec, entries in await _gather_with_progress(
                    (_dns(d) for d in domains), "DNS records", use_prog):
                dns_records[d] = rec
                if entries is not None:
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

            # Phishing read-out, once both the email posture and the MX
            # infrastructure are known — the gateway is what decides whether
            # lookalike mail is filtered on arrival, and it comes from mail_infra.
            for d, entry in email.items():
                entry["phishing_posture"] = phishing_posture(entry, mail_infra.get(d))
                services = ((entry.get("dmarc_vendors") or [])
                            + (entry.get("spf_vendors") or []))
                if services:
                    log(f"[i] email services {d}: {', '.join(services)}")

        # ---- DNS zone transfer (AXFR) ----
        # One query per authoritative nameserver, reusing the NS list the DNS
        # snapshot above already collected. A server that answers hands over
        # every internal name in the zone at once, so this is critical when it
        # lands — and cheap when it doesn't.
        axfr = {}
        if not args.passive_only:
            for d in domains:
                ns_names = (dns_records.get(d) or {}).get("ns") or []
                result = await zone_transfer(d, ns_names, ns)
                axfr[d] = result
                if result["transferred"]:
                    total = sum(result["transferred"].values())
                    log(f"[!] AXFR {d}: zone transfer ALLOWED by "
                        f"{', '.join(result['transferred'])} — {total} record(s) "
                        f"disclosed (critical)")
                elif result["refused"] and not result["errors"]:
                    log(f"[+] AXFR {d}: refused by all {len(result['refused'])} "
                        f"nameserver(s) — correctly restricted")
                elif result["refused"] or result["errors"]:
                    # Never call an unreachable nameserver a refusal: that would
                    # report a blocked network path as a clean result.
                    parts = ([f"{len(result['refused'])} refused"] if result["refused"] else []) \
                        + ([f"{len(result['errors'])} unreachable"] if result["errors"] else [])
                    log(f"[!] AXFR {d}: {', '.join(parts)} — inconclusive for the "
                        f"unreachable one(s), not evidence that transfers are refused")

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

        # ---- OSINT user enumeration ----
        # The keyed sources (hunter/rocketreach/github) keep the "presence of a
        # key = opt-in" convention. The website scrape is keyless and runs on
        # any active scope, because otherwise a client with no API keys got an
        # empty people list that read as "nobody is exposed" when in truth
        # nothing had been looked at.
        people = []
        keyed = keys.get("hunter") or keys.get("rocketreach") or keys.get("github")
        if keyed:
            for d in domains:
                people += await enumerate_people(client, d, keys, gh_limiter, args.company_name)

        if not args.passive_only:
            known = {p.email for p in people}
            scraped_total, roles_total = 0, 0
            for d in domains:
                scraped = await scrape_site_emails(probe_client, d, list(hosts.values()))
                fresh = scraped - known
                staff, roles = split_role_accounts(fresh)
                roles_total += len(roles)
                scraped_total += len(fresh)
                for email in staff + roles:
                    people.append(Person(email=email, source={"website"}))
                    known.add(email)
                # An address already known from a keyed source is corroborated,
                # not duplicated — record that the target published it itself.
                for p in people:
                    if p.email in scraped:
                        p.source.add("website")
            if scraped_total:
                log(f"[+] website email scrape: {scraped_total} new address(es) published on "
                    f"the target's own pages"
                    + (f" ({roles_total} role/shared mailbox(es))" if roles_total else ""))

        if people:
            log(f"[+] people-enum: {len(people)} company-affiliated email(s) discovered")
        elif keyed or not args.passive_only:
            # Silence here used to be indistinguishable from "the phase never
            # ran" — and 0 exposed users is a claim worth stating explicitly.
            log("[i] people-enum: 0 addresses found "
                + ("(keyed sources + website scrape both came back empty)" if keyed
                   else "(website scrape only — no hunter/rocketreach/github key configured)"))

        if args.verify_emails and people and not args.passive_only:
            for d in domains:
                d_people = [p for p in people if p.email.endswith(f"@{d}")]
                if not d_people:
                    continue
                statuses = await verify_emails(d, [p.email for p in d_people], ns,
                                               mail_from=getattr(args, "mail_from", None))
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

                # ---- CISA KEV + EPSS: rank by real-world exploitability ----
                # KEV = known exploited in the wild (the strongest lead); EPSS =
                # probability of exploitation. Both keyless, fetched once for all
                # resolved CVEs and annotated onto each nvd_cves dict.
                kev_set = await load_kev(client)
                epss = await epss_scores(client, unique_cve_ids)
                for h in nvd_hosts:
                    for c in (h.nvd_cves or []):
                        cid = c.get("id")
                        if cid in kev_set:
                            c["kev"] = True
                        if cid in epss:
                            c["epss"] = epss[cid]
                n_kev = len(set(unique_cve_ids) & kev_set)
                if n_kev:
                    log(f"[!] {n_kev} resolved CVE(s) in the CISA KEV catalog "
                        f"(known exploited in the wild) — prioritise these")

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
    security_txts = []
    if not args.passive_only:
        live = [h for h in host_list if h.http_status and not h.wildcard]
        results = await asyncio.gather(*[auth_surface(probe_client, h.subdomain) for h in live])
        auth_surfaces = [a for a in results if a]
        if auth_surfaces:
            idps = ", ".join(sorted({a.get("idp") or "unknown" for a in auth_surfaces}))
            log(f"[+] auth-surface: {len(auth_surfaces)} host(s) expose OIDC/SSO discovery ({idps})")

        # security.txt (RFC 9116) on the same live hosts — a file published
        # deliberately, so this is discovery. It names the disclosure channel a
        # report should go to, and its Policy/Canonical URLs often point at
        # hosts nothing else surfaced.
        st = await asyncio.gather(*[security_txt(probe_client, h.subdomain) for h in live])
        security_txts = [s for s in st if s]
        if security_txts:
            n_expired = sum(1 for s in security_txts if s.get("expired"))
            log(f"[+] security.txt: {len(security_txts)} host(s) publish one"
                + (f", {n_expired} expired" if n_expired else ""))

    # ---- Entry-point summary (red-team signal: what to chase first) ----
    entry_points = summarize_entry_points(host_list, cf, buckets, breach, github_findings,
                                          nuclei, dorks, auth_surfaces, whois=whois,
                                          axfr=axfr)
    if entry_points:
        log(f"[!] {len(entry_points)} potential entry point(s) identified:")
        for ep in entry_points:
            log(f"    [ENTRY POINT] [{ep['severity'].upper()}] {ep['target']} — {ep['summary']}")
    else:
        log("[+] no high-confidence entry points identified this pass")

    # ---- Composite attack-surface score (rank hosts: work these first) ----
    for h in host_list:
        h.risk_score, h.risk_factors = risk_score(h, entry_points_for_host(h, entry_points))

    # ---- In-scope tracking-pixel correlation (shared analytics = shared owner) ----
    tracking_correlation = correlate_tracking_ids(host_list)
    if tracking_correlation:
        log(f"[+] {len(tracking_correlation)} tracking ID(s) shared across in-scope hosts")

    # ---- Diff vs previous run ----
    diff = {}
    ip_targets = getattr(args, "ip_targets", None)
    if args.diff:
        diff = diff_snapshot(load_prev_snapshot(domains, ip_targets), host_list)
    save_snapshot(domains, host_list, ip_targets)

    return {"hosts": host_list, "per_source": dict(per_source), "cf": cf,
            "email": email, "github": github_findings, "buckets": buckets,
            "breach": breach, "asn": asn_info, "favicon_pivots": favicon_pivots,
            "nuclei": nuclei, "diff": diff, "entry_points": entry_points, "people": people,
            "whois": whois, "dorks": dorks, "dns": dns_records, "mail_infra": mail_infra,
            "vt": vt_intel, "auth_surface": auth_surfaces, "certs": certs,
            "axfr": axfr, "security_txt": security_txts,
            "tracking_correlation": tracking_correlation}


