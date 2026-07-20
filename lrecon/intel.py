from __future__ import annotations
import asyncio, ipaddress, json
import httpx
from .common import *
from .sources import get_resolver, resolve_full

# --------------------------------------------------------------------------- #
# Cloudflare origin discovery (origin IP disclosure -> WAF bypass)
# --------------------------------------------------------------------------- #
async def load_cf_ranges(client) -> list:
    nets = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        try:
            r = await client.get(url, timeout=15)
            if r.status_code == 200:
                for line in r.text.split():
                    try:
                        nets.append(ipaddress.ip_network(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
    if not nets:
        nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    return nets


def in_cf(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except Exception:
        return False


async def cloudflare_origin_analysis(client, probe_client, domains, hosts, keys, cf_nets,
                                     active, resolver_ns) -> dict:
    """
    Passive candidate collection + optional active confirmation.
    Candidate sources (passive / no target touch):
      * in-scope subdomains resolving to non-Cloudflare IPs (unproxied leak)
      * SPF ip4:/ip6: literals and MX host IPs on the apex
      * Shodan cert search: ssl.cert.subject.CN:"domain" -> non-CF IPs
    Confirmation (active, touches candidate IP): spoofed Host header.

    `client` (cert-verified) is used for the Shodan API lookup; `probe_client`
    (unverified) is used to touch candidate origin IPs directly, since those
    rarely present a cert matching the spoofed Host header.
    """
    result = {"detected": False, "fronted": [], "candidates": {}}

    fronted = [h.subdomain for h in hosts.values()
               if not h.wildcard and any(in_cf(ip, cf_nets) for ip in h.ips)]
    result["fronted"] = sorted(fronted)
    result["detected"] = bool(fronted)
    if not result["detected"]:
        return result

    cands = defaultdict(lambda: {"sources": set(), "confirmed": False, "evidence": None})

    # 1. unproxied in-scope subdomains
    for h in hosts.values():
        if h.wildcard:
            continue
        for ip in h.ips:
            try:
                if not in_cf(ip, cf_nets) and ipaddress.ip_address(ip).is_global:
                    cands[ip]["sources"].add(f"unproxied:{h.subdomain}")
            except Exception:
                pass

    # 2. SPF + MX from apex (DNS; low-touch, active mode only)
    if active and _HAVE_DNS:
        res = get_resolver(resolver_ns)
        for d in domains:
            try:
                for rr in await res.resolve(d, "TXT"):
                    txt = "".join(s.decode(errors="ignore") for s in rr.strings)
                    if "v=spf1" in txt:
                        for tok in txt.split():
                            if tok.startswith(("ip4:", "ip6:")):
                                ip = tok.split(":", 1)[1].split("/")[0]
                                if not in_cf(ip, cf_nets):
                                    cands[ip]["sources"].add(f"spf:{d}")
            except Exception:
                pass
            try:
                for rr in await res.resolve(d, "MX"):
                    mx = str(rr.exchange).rstrip(".")
                    mxips, _ = await resolve_full(mx, resolver_ns)
                    for ip in mxips:
                        if not in_cf(ip, cf_nets):
                            cands[ip]["sources"].add(f"mx:{mx}")
            except Exception:
                pass

    # 3. Shodan cert search (passive; costs query credits)
    if keys.get("shodan"):
        for d in domains:
            try:
                r = await client.get("https://api.shodan.io/shodan/host/search",
                                    params={"key": keys["shodan"],
                                            "query": f'ssl.cert.subject.CN:"{d}"'},
                                    timeout=25)
                if r.status_code == 200:
                    for m in r.json().get("matches", []):
                        ip = m.get("ip_str")
                        if ip and not in_cf(ip, cf_nets):
                            cands[ip]["sources"].add(f"shodan-cert:{d}")
            except Exception:
                pass

    # 4. active confirmation: spoofed Host header to candidate IP
    if active and cands:
        primary = domains[0]
        for ip in list(cands):
            for scheme in ("https", "http"):
                try:
                    r = await probe_client.get(f"{scheme}://{ip}", headers={"Host": primary},
                                        timeout=8, follow_redirects=False)
                    server = (r.headers.get("server") or "").lower()
                    if r.status_code < 500 and "cloudflare" not in server:
                        cands[ip]["confirmed"] = True
                        cands[ip]["evidence"] = (f"Host: {primary} -> {scheme} "
                                                 f"{r.status_code}, server={server or 'n/a'}")
                        break
                except Exception:
                    continue

    result["candidates"] = {ip: {"sources": sorted(v["sources"]),
                                 "confirmed": v["confirmed"], "evidence": v["evidence"]}
                            for ip, v in cands.items()}
    return result



# --------------------------------------------------------------------------- #
# Email security posture (SPF / DKIM / DMARC) — DNS, low-touch
# --------------------------------------------------------------------------- #
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]


async def email_security(domain: str, resolver_ns) -> dict:
    if not _HAVE_DNS:
        return {}
    res = get_resolver(resolver_ns)
    out = {"domain": domain, "spf": None, "dmarc": None, "dkim": False, "issues": []}

    async def txt(name):
        try:
            return ["".join(s.decode(errors="ignore") for s in rr.strings)
                    for rr in await res.resolve(name, "TXT")]
        except Exception:
            return []

    spf = next((t for t in await txt(domain) if "v=spf1" in t), None)
    out["spf"] = spf
    if not spf:
        out["issues"].append("No SPF record (spoofing risk)")
    elif "+all" in spf:
        out["issues"].append("SPF +all — permits any sender (critical)")
    elif "~all" not in spf and "-all" not in spf:
        out["issues"].append("SPF missing hard/soft fail (~all/-all)")

    dmarc = next((t for t in await txt(f"_dmarc.{domain}") if "v=DMARC1" in t), None)
    out["dmarc"] = dmarc
    if not dmarc:
        out["issues"].append("No DMARC record (spoofing risk)")
    elif "p=none" in dmarc:
        out["issues"].append("DMARC p=none — monitoring only, no enforcement")

    for sel in DKIM_SELECTORS:
        if any("v=DKIM1" in t or "k=rsa" in t for t in await txt(f"{sel}._domainkey.{domain}")):
            out["dkim"] = True
            break
    if not out["dkim"]:
        out["issues"].append("No DKIM on common selectors (inconclusive)")

    sev = len([i for i in out["issues"] if "risk" in i or "critical" in i])
    out["grade"] = "FAIL" if sev else ("WARN" if out["issues"] else "PASS")
    return out



# --------------------------------------------------------------------------- #
# GitHub code dorking (needs token) — T1593.003
# --------------------------------------------------------------------------- #
async def github_dork(client, domain: str, token: str, limiter) -> list:
    out = []
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github.v3+json",
               "User-Agent": "lrecon"}
    for q in (f'"{domain}"', f'"{domain}" password', f'"{domain}" api_key'):
        await limiter.wait()
        try:
            r = await client.get("https://api.github.com/search/code",
                                params={"q": q, "per_page": 20}, headers=headers, timeout=25)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    out.append({"repo": item.get("repository", {}).get("full_name"),
                                "path": item.get("path"),
                                "url": item.get("html_url"),
                                "query": q})
            elif r.status_code == 403:
                log("[!] github: rate limited")
                break
        except Exception as e:
            log(f"[!] github dork: {e}")
            break
    # dedupe by url
    seen, uniq = set(), []
    for it in out:
        if it["url"] not in seen:
            seen.add(it["url"])
            uniq.append(it)
    return uniq



# --------------------------------------------------------------------------- #
# Cloud bucket enumeration (permutation + HEAD) — low-touch (hits provider)
# --------------------------------------------------------------------------- #
BUCKET_SUFFIXES = ["", "-backup", "-backups", "-dev", "-prod", "-staging", "-assets",
                   "-static", "-data", "-media", "-uploads", "-logs", "-files",
                   "-public", "-private", "-internal", "-www"]


def bucket_candidates(keywords) -> list:
    names = set()
    for kw in keywords:
        kw = kw.lower().replace(".", "-")
        for suf in BUCKET_SUFFIXES:
            names.add(f"{kw}{suf}")
    return sorted(names)


async def bucket_enum(client, keywords) -> list:
    out = []
    names = bucket_candidates(keywords)
    sem = asyncio.Semaphore(40)

    async def check(name):
        async with sem:
            probes = [
                ("s3", f"https://{name}.s3.amazonaws.com"),
                ("gcs", f"https://storage.googleapis.com/{name}"),
                ("azure", f"https://{name}.blob.core.windows.net/?comp=list&restype=container"),
            ]
            for provider, url in probes:
                try:
                    r = await client.get(url, timeout=8)
                    if r.status_code in (200, 403):
                        public = r.status_code == 200 and ("<ListBucketResult" in r.text
                                                           or "<EnumerationResults" in r.text
                                                           or "<Contents" in r.text)
                        out.append({"name": name, "provider": provider, "url": url,
                                    "status": r.status_code, "public": public})
                except Exception:
                    pass
    await asyncio.gather(*(check(n) for n in names))
    return out



# --------------------------------------------------------------------------- #
# Breach exposure (HIBP breaches-by-domain, keyless list)
# --------------------------------------------------------------------------- #
async def hibp_breaches(client, domain: str) -> list:
    out = []
    try:
        r = await client.get("https://haveibeenpwned.com/api/v3/breaches",
                            params={"domain": domain},
                            headers={"User-Agent": "lrecon"}, timeout=20)
        if r.status_code == 200:
            for b in r.json():
                out.append({"name": b.get("Name"), "date": b.get("BreachDate"),
                            "pwned": b.get("PwnCount"),
                            "data": b.get("DataClasses", [])})
    except Exception as e:
        log(f"[!] hibp {domain}: {e}")
    return out



# --------------------------------------------------------------------------- #
# Entry-point summary — the highest-signal findings, ranked, across all phases
# --------------------------------------------------------------------------- #
ENTRY_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def summarize_entry_points(hosts, cf, buckets, breach, github_findings, nuclei) -> list:
    """
    Pull the findings that represent a likely initial-access vector out of the
    full result set into one ranked list, so they're stated explicitly instead
    of only implied by per-phase stats. Each entry: type, target, severity,
    summary, attck (ATT&CK technique).
    """
    out = []

    for h in hosts:
        if h.takeover:
            sev = "critical" if "unclaimed-service signature matched" in h.takeover else "high"
            out.append({"type": "subdomain-takeover", "target": h.subdomain, "severity": sev,
                       "summary": h.takeover, "attck": "T1584.001"})

    if cf.get("detected"):
        for ip, v in cf.get("candidates", {}).items():
            if v["confirmed"]:
                out.append({"type": "cloudflare-origin-bypass", "target": ip, "severity": "high",
                           "summary": f"Origin IP reachable outside Cloudflare — WAF/DDoS bypass "
                                      f"({v['evidence']})",
                           "attck": "T1590.005"})

    for b in buckets:
        if b["public"]:
            out.append({"type": "public-bucket", "target": b["name"], "severity": "high",
                       "summary": f"{b['provider']} bucket publicly listable at {b['url']}",
                       "attck": "T1530"})

    for n in (nuclei or []):
        sev = (n.get("severity") or "").lower()
        if sev in ("critical", "high"):
            out.append({"type": "nuclei-finding", "target": n.get("host") or "?", "severity": sev,
                       "summary": f"{n.get('name') or n.get('template')} "
                                  f"({n.get('cve') or 'no CVE'}) at {n.get('matched')}",
                       "attck": "T1190"})

    for h in hosts:
        if h.vulns:
            out.append({"type": "known-cve", "target": h.subdomain, "severity": "medium",
                       "summary": f"{len(h.vulns)} reported CVE(s): {', '.join(h.vulns[:5])}",
                       "attck": "T1190"})

    for d, bs in (breach or {}).items():
        if bs:
            out.append({"type": "breach-exposure", "target": d, "severity": "medium",
                       "summary": f"{len(bs)} known breach(es) — password-spray candidate list",
                       "attck": "T1110.003"})

    if github_findings:
        repos = sorted({g["repo"] for g in github_findings if g.get("repo")})
        out.append({"type": "github-code-exposure",
                   "target": ", ".join(repos[:5]) + ("…" if len(repos) > 5 else ""),
                   "severity": "medium",
                   "summary": f"{len(github_findings)} public code hit(s) referencing scope across "
                              f"{len(repos)} repo(s) — review for leaked credentials",
                   "attck": "T1593.003"})

    out.sort(key=lambda e: ENTRY_SEVERITY_ORDER.get(e["severity"], 9))
    return out

