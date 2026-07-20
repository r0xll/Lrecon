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
from . import backends

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


async def run(domains, args, keys) -> list:
    shodan_key = keys.get("shodan")
    ipinfo_token = keys.get("ipinfo")
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

        if shodan_key:
            try:
                r = await client.get(f"https://api.shodan.io/api-info?key={shodan_key}", timeout=15)
                if r.status_code == 200:
                    log(f"[+] Shodan key OK — query credits: {r.json().get('query_credits','?')}")
                elif r.status_code == 401:
                    log("[!] Shodan key rejected — falling back to keyless InternetDB")
                    shodan_key = None
            except Exception:
                pass

        # ---- Phase 1: passive enum (with source attribution) ----
        host_sources, per_source = await passive_enum(client, domains, keys)
        hosts = {n: Host(subdomain=n, source=set(srcs)) for n, srcs in host_sources.items()}
        breakdown = "  ".join(f"{s}={per_source[s]}" for s in sorted(per_source)) or "none"
        log(f"[+] {len(hosts)} unique subdomains  |  by source: {breakdown}")
        if per_source.get("crtsh", 0) == 0:
            log("[!] crt.sh returned 0 (down/rate-limited?) — other CT sources covering")

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

        # ---- Phase 3: enrichment on UNIQUE IPs ----
        ip_to_hosts = defaultdict(list)
        for h in hosts.values():
            if not h.wildcard:
                for ip in h.ips:
                    ip_to_hosts[ip].append(h)
        unique_ips = list(ip_to_hosts)
        if unique_ips:
            ports_src = "shodan" if shodan_key else "internetdb"
            layers = ["ports/CVE:" + ports_src] + (["ipinfo"] if ipinfo_token else [])
            enrich_sem = asyncio.Semaphore(args.concurrency)

            async def enrich_ip(ip):
                async with enrich_sem:
                    ports_data = (await enrich_shodan_host(client, ip, shodan_key, shodan_limiter)
                                  if shodan_key else await enrich_internetdb(client, ip))
                    info = await enrich_ipinfo(client, ip, ipinfo_token) if ipinfo_token else {}
                return ip, ports_data, info
            results = await _gather_with_progress(
                (enrich_ip(ip) for ip in unique_ips),
                f"enriching {len(unique_ips)} unique IPs ({', '.join(layers)})", use_prog)
            for ip, ports_data, info in results:
                for h in ip_to_hosts[ip]:
                    apply_ports(h, ports_data, ports_src)
                    apply_ipinfo(h, info)

        # ---- Phase 4: active probe / port scan / favicon ----
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

        github_findings = []
        if keys.get("github"):
            gh_limiter = RateLimiter(per_second=0.2)          # code search ~10/min
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

        breach = {}
        for d in domains:
            b = await hibp_breaches(client, d)
            if b:
                breach[d] = b
        if breach:
            log(f"[+] breach: {sum(len(v) for v in breach.values())} known breach(es) for scope")

        # ---- NVD CVE enrichment (opt-in; cached) ----
        if args.nvd and not args.passive_only:
            nvd_cache = {}
            nvd_limiter = RateLimiter(per_second=0.16)        # ~5 req / 30s keyless
            cpe_hosts = [h for h in hosts.values() if h.cpes]
            async def do_nvd(h):
                seen = {}
                for cpe in h.cpes[:5]:
                    for cve in await nvd_lookup(client, cpe, nvd_cache, nvd_limiter):
                        seen[cve["id"]] = cve
                h.nvd_cves = sorted(seen.values(), key=lambda c: -(c["cvss"] or 0))
            if cpe_hosts:
                await _gather_with_progress((do_nvd(h) for h in cpe_hosts),
                                            f"NVD lookup ({len(cpe_hosts)} hosts)", use_prog)

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

    # ---- Diff vs previous run ----
    host_list = sorted(hosts.values(), key=lambda h: h.subdomain)
    diff = {}
    if args.diff:
        diff = diff_snapshot(load_prev_snapshot(domains), host_list)
    save_snapshot(domains, host_list)

    return {"hosts": host_list, "per_source": dict(per_source), "cf": cf,
            "email": email, "github": github_findings, "buckets": buckets,
            "breach": breach, "asn": asn_info, "favicon_pivots": favicon_pivots,
            "nuclei": nuclei, "diff": diff}


