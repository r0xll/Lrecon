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
# Domain registration data (WHOIS via RDAP) — keyless, third-party registry
# only, never touches the target's own infrastructure. RDAP is the
# structured, JSON-based successor to WHOIS; rdap.org is a public bootstrap
# redirector to the authoritative RDAP server for whatever TLD the domain is
# under, so one endpoint covers the large majority of TLDs without needing to
# chase IANA referrals ourselves.
# --------------------------------------------------------------------------- #
def _rdap_entity_name(entity: dict) -> str | None:
    """Registrar/registrant name is buried in jCard format: vcardArray[1] is
    a list of [field, params, type, value, ...] entries; find the "fn" one."""
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] == "fn" and item[3]:
            return item[3]
    return None


def _parse_rdap(data: dict) -> dict:
    out = {"registrar": None, "created": None, "expires": None,
          "last_changed": None, "nameservers": [], "status": []}
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        if action == "registration":
            out["created"] = ev.get("eventDate")
        elif action == "expiration":
            out["expires"] = ev.get("eventDate")
        elif action == "last changed":
            out["last_changed"] = ev.get("eventDate")
    out["nameservers"] = sorted({ns["ldhName"].lower() for ns in data.get("nameservers", []) or []
                                 if ns.get("ldhName")})
    out["status"] = data.get("status") or []
    registrar = next((e for e in data.get("entities", []) or [] if "registrar" in (e.get("roles") or [])),
                     None)
    if registrar:
        out["registrar"] = _rdap_entity_name(registrar)
    return out


async def rdap_lookup(client, domain: str) -> dict:
    """
    Overrides the shared client's default follow_redirects=False for this one
    call — rdap.org responds with a redirect to the authoritative registry
    (e.g. rdap.verisign.com for .com), confirmed live against example.com.
    Returns {} on any failure — many domains (privacy-protected registrants,
    some ccTLDs without RDAP support yet) simply won't resolve; that's
    expected, not an error worth logging loudly.
    """
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", timeout=20, follow_redirects=True)
        if r.status_code == 200:
            return _parse_rdap(r.json())
    except Exception as e:
        log(f"[!] whois/rdap {domain}: {e}")
    return {}


def domain_expiring_soon(expires: str | None, within_days: int = 30) -> bool:
    if not expires:
        return False
    try:
        from datetime import datetime, timezone
        exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return (exp - datetime.now(timezone.utc)).days <= within_days
    except Exception:
        return False



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
_CVSS_SEVERITY = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"))


def _cve_severity(cvss, has_poc: bool = False) -> str:
    if cvss is None:
        sev = "medium"                               # no CVSS data (e.g. Shodan/InternetDB vulns list)
    else:
        sev = "low"
        for threshold, s in _CVSS_SEVERITY:
            if cvss >= threshold:
                sev = s
                break
    # A working public exploit is a stronger red-team signal than raw CVSS
    # alone — floor at "high" rather than leaving it at medium/low.
    if has_poc and ENTRY_SEVERITY_ORDER[sev] > ENTRY_SEVERITY_ORDER["high"]:
        sev = "high"
    return sev


def summarize_entry_points(hosts, cf, buckets, breach, github_findings, nuclei, dorks=None) -> list:
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

    for d in (dorks or []):
        out.append({"type": "dork-hit", "target": d["link"], "severity": d["severity"],
                   "summary": f"{d['category']}: {d['title']} — {d['snippet']}",
                   "attck": "T1593.002"})

    known_cve_cap = 5
    for h in hosts:
        nvd = h.nvd_cves or []
        nvd_by_id = {c["id"]: c for c in nvd if c.get("id")}
        all_ids = set(h.vulns) | set(nvd_by_id)
        # DoS-only CVEs aren't useful as an initial-access lead — drop them from
        # consideration (and from severity ranking) wherever NVD data classifies
        # them as such. IDs we have no NVD data for (no --nvd, or lookup miss)
        # can't be classified and are kept as-is.
        dos_ids = {cid for cid in all_ids if nvd_by_id.get(cid, {}).get("dos_only")}
        cve_ids = all_ids - dos_ids
        if not cve_ids:
            continue
        # PoC-confirmed CVEs first — a working public exploit outranks raw
        # CVSS as a red-team signal — then by CVSS descending, unscored last.
        ranked = sorted(cve_ids, key=lambda cid: (
            0 if nvd_by_id.get(cid, {}).get("poc") else 1,
            -(nvd_by_id.get(cid, {}).get("cvss") if nvd_by_id.get(cid, {}).get("cvss") is not None else -1),
            cid))
        cvss_values = [nvd_by_id[cid]["cvss"] for cid in cve_ids
                       if nvd_by_id.get(cid, {}).get("cvss") is not None]
        max_cvss = max(cvss_values) if cvss_values else None
        poc_ids = [cid for cid in cve_ids if nvd_by_id.get(cid, {}).get("poc")]
        unscored = len(cve_ids) - len(cvss_values)

        severity = min(
            (_cve_severity(nvd_by_id.get(cid, {}).get("cvss"), has_poc=bool(nvd_by_id.get(cid, {}).get("poc")))
             for cid in cve_ids),
            key=lambda s: ENTRY_SEVERITY_ORDER.get(s, 9))

        cvss_note = f" (max CVSS {max_cvss})" if max_cvss is not None else ""
        poc_note = f" [{len(poc_ids)} with public PoC]" if poc_ids else ""
        dos_note = f" [{len(dos_ids)} DoS-only CVE(s) excluded]" if dos_ids else ""
        unscored_note = f" [{unscored} unscored — run --nvd for full data]" if unscored and not cvss_values else \
                         (f" [{unscored} unscored]" if unscored else "")
        detail = "; ".join(
            cid + (f" (CVSS {nvd_by_id[cid]['cvss']})" if nvd_by_id.get(cid, {}).get("cvss") is not None else "")
            + (" [PoC]" if nvd_by_id.get(cid, {}).get("poc") else "")
            + (f" — {nvd_by_id[cid]['desc']}" if nvd_by_id.get(cid, {}).get("desc") else "")
            for cid in ranked[:known_cve_cap])
        if len(ranked) > known_cve_cap:
            detail += f"; +{len(ranked) - known_cve_cap} more"
        out.append({"type": "known-cve", "target": h.subdomain,
                   "severity": severity,
                   "summary": f"{len(ranked)} known CVE(s){cvss_note}{poc_note}{dos_note}{unscored_note}: {detail}",
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

