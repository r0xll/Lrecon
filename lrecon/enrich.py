from __future__ import annotations
import asyncio, base64, ipaddress, json
import httpx
from .common import *

# --------------------------------------------------------------------------- #
# Phase 3 — enrichment per UNIQUE IP
# --------------------------------------------------------------------------- #
async def enrich_ipinfo(client, ip, token) -> dict:
    """ASN / org / reverse-DNS / geo. Reliable regardless of scan coverage."""
    url = f"https://ipinfo.io/{ip}/json" + (f"?token={token}" if token else "")
    try:
        r = await client.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


async def enrich_shodan_host(client, ip, key, limiter) -> dict:
    for attempt in range(3):
        await limiter.wait()
        try:
            r = await client.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                await asyncio.sleep(2 * (attempt + 1))
                continue
            return {}
        except Exception:
            return {}
    return {}


async def enrich_internetdb(client, ip) -> dict:
    try:
        r = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def apply_ipinfo(h: Host, data: dict, ip: str | None = None) -> None:
    if not data:
        return
    h.enrich_src.add("ipinfo")
    h.source.add("ipinfo")
    org = data.get("org")                           # e.g. "AS15169 Google LLC"
    if org:
        parts = org.split(" ", 1)
        if parts[0].startswith("AS"):
            org_name = parts[1] if len(parts) > 1 else org
            h.asn = parts[0]
            h.org = h.org or org_name
            if ip:
                h.ip_asn[ip] = parts[0]
                h.ip_org[ip] = org_name
        else:
            h.org = h.org or org
            if ip:
                h.ip_org[ip] = org
    h.rdns = h.rdns or data.get("hostname")
    h.country = h.country or data.get("country")
    if ip and data.get("country"):
        h.ip_country[ip] = data["country"]


def apply_ports(h: Host, data: dict, src: str) -> None:
    if not data:
        return
    h.enrich_src.add(src)
    h.source.add(src)
    h.ports = sorted(set(h.ports) | set(data.get("ports", [])))
    h.vulns = sorted(set(h.vulns) | set(data.get("vulns", []) or []))
    if src == "shodan":
        h.isp = h.isp or data.get("isp")
        h.org = h.org or data.get("org")
    else:
        h.cpes = sorted(set(h.cpes) | set(data.get("cpes", [])))



# --------------------------------------------------------------------------- #
# Tech-stack confirmation — cross-references Shodan/InternetDB-reported CPEs
# (the basis for h.vulns/h.cpes-derived CVE hits) against the live tech-detect
# probe (h.tech, Wappalyzer via the ProjectDiscovery httpx backend's -td flag).
# Shodan/InternetDB data comes from a periodic internet-wide scan that can be
# weeks old; this flags whether the reported vulnerable software still looks
# live, cutting down manual CVE triage instead of chasing every stale banner.
# --------------------------------------------------------------------------- #
def _cpe_vendor_product(cpe: str) -> tuple:
    """(vendor, product) from a CPE 2.2 or 2.3 string, lowercased with
    underscores turned to spaces for loose matching against Wappalyzer-style
    tech names — e.g. cpe:2.3:a:apache:http_server:2.4.49:... ->
    ("apache", "http server")."""
    body = cpe[5:] if cpe.startswith("cpe:/") else cpe.removeprefix("cpe:2.3:")
    parts = body.split(":")

    def norm(x):
        return x.replace("_", " ").lower() if x and x not in ("*", "-") else None

    vendor = norm(parts[1]) if len(parts) > 1 else None
    product = norm(parts[2]) if len(parts) > 2 else None
    return vendor, product


def tech_stack_confirms_cpe(tech: list, cpe: str) -> bool:
    """True if any live-detected tech entry (e.g. "WordPress:6.4.2") names
    the same vendor/product as the CPE — i.e. what's actually being served
    right now still looks like the software the CVE data is about."""
    vendor, product = _cpe_vendor_product(cpe)
    needles = [n for n in (vendor, product) if n]
    if not needles:
        return False
    for entry in tech or []:
        name = entry.split(":", 1)[0].replace("_", " ").lower()
        if any(needle in name or name in needle for needle in needles):
            return True
    return False


def confirm_tech_stack(h: Host) -> bool | None:
    """
    True  — at least one Shodan/InternetDB-reported CPE matches something
            live-detected — the CVE-relevant software still looks present.
    False — CPEs were reported but none matched what's live right now — the
            banner may be stale, already patched, or the service replaced;
            worth a second look before spending validation time on it.
    None  — nothing to compare (no live tech-detect data, or no CPEs
            reported for this host).
    """
    if not h.tech or not h.cpes:
        return None
    return any(tech_stack_confirms_cpe(h.tech, cpe) for cpe in h.cpes)



# --------------------------------------------------------------------------- #
# Favicon hashing (Shodan-compatible mmh3) + pivot
# --------------------------------------------------------------------------- #
def _favicon_mmh3(content: bytes) -> int:
    import base64
    try:
        import mmh3
    except Exception:
        return None
    return mmh3.hash(base64.encodebytes(content))


async def favicon_hash(client, base_url: str):
    try:
        r = await client.get(base_url.rstrip("/") + "/favicon.ico", timeout=10,
                            follow_redirects=True)
        if r.status_code == 200 and r.content:
            return _favicon_mmh3(r.content)
    except Exception:
        pass
    return None


# Favicons are tiny; a big body at /favicon.ico is a mislabelled page or an
# error doc, not an icon. Cap so a self-contained HTML report can't be bloated
# by a stray multi-MB response embedded as a data URI.
FAVICON_MAX_BYTES = 64 * 1024


def seed_favicon_sources(hosts, domains) -> dict:
    """`{favicon_hash: [seed host(s) serving it]}`, restricted to the seed
    domains and their `www`.

    Deliberately NOT every enumerated host: a subdomain running GitLab, cPanel
    or Google Workspace serves that vendor's stock favicon, and pivoting on it
    floods the results with unrelated hosts running the same software. A favicon
    is a company fingerprint only when it's the company's — served by a domain
    the operator actually named. `www.<seed>` is included because it's the same
    canonical site, not a vendor subdomain.
    """
    import collections
    seed_hosts = set(domains) | {f"www.{d}" for d in domains}
    out = collections.defaultdict(list)
    for h in hosts:
        if getattr(h, "favicon_hash", None) and h.subdomain in seed_hosts:
            out[h.favicon_hash].append(h.subdomain)
    return {fh: sorted(srcs) for fh, srcs in out.items()}


async def favicon_data_uri(client, base_url: str) -> str | None:
    """The favicon a host serves, as a `data:` URI for inline display — so a
    report reader can see the icon a pivot hash actually corresponds to and
    confirm it's the org's logo rather than a framework default.

    Reuses the same `/favicon.ico` fetch as favicon_hash(); returns None on
    non-200, an empty/oversized body, or any error. The MIME type comes from the
    response so an SVG or PNG favicon renders correctly, defaulting to
    `image/x-icon` for the classic `.ico`.
    """
    import base64
    try:
        r = await client.get(base_url.rstrip("/") + "/favicon.ico", timeout=10,
                            follow_redirects=True)
        if r.status_code != 200 or not r.content or len(r.content) > FAVICON_MAX_BYTES:
            return None
        mime = (r.headers.get("content-type") or "image/x-icon").split(";")[0].strip()
        if not mime.startswith("image/"):
            mime = "image/x-icon"
        b64 = base64.b64encode(r.content).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except Exception:
        return None


# A favicon shared by more hosts than this is a framework/CDN default (stock
# nginx, WordPress, a JS framework), not a company marker — pivoting on it drags
# in tens of thousands of unrelated hosts. Shodan returns the total up front, so
# we can decide to skip before paging a single result.
FAVICON_MAX_MATCHES = 500


def classify_favicon_matches(matches: list, domains, name_in_scope) -> tuple:
    """Tag each match with a scope and pick the expansion candidates.

    Scope is `in-scope` (a hostname is under a seed domain), `cross-domain` (has
    hostnames, none in scope), or `ip-only` (no hostname to reason about).
    Returns `(tagged_matches, {hostname: ip})` — the second is the cross-domain
    hosts, and *only* those: an in-scope name is already enumerated, and a bare
    IP is nothing to probe by hostname.

    Kept as a pure function precisely because it is the ROE-relevant decision —
    which hosts become probe candidates — so it can be tested without standing
    up the whole pipeline. `name_in_scope` is injected to avoid an import cycle.
    """
    expand = {}
    for m in matches:
        names = m.get("hostnames") or []
        if any(name_in_scope(n, d) for n in names for d in domains):
            m["scope"] = "in-scope"
        elif names:
            m["scope"] = "cross-domain"
            for n in names:
                expand.setdefault(n, m["ip"])
        else:
            m["scope"] = "ip-only"
    return matches, expand


async def shodan_favicon_pivot(client, fhash: int, key: str, cf_nets,
                               limiter=None) -> dict:
    """Hosts across the internet serving a given favicon — the point being to
    find a company's assets whose names don't resemble the seed domains.

    Returns one of:
      * ``{"skipped": total}`` — too common to be a marker (see FAVICON_MAX_MATCHES).
      * ``{"matches": [...]}``  — each a dict of the evidence needed to judge
        ownership: ip, hostnames, org, cert CN, title, port, and whether it sits
        behind Cloudflare. The old version returned bare IPs and dropped all of
        this, which is exactly what a favicon pivot exists to surface.
      * ``{}`` — no key, error, or genuinely nothing.

    Cloudflare hosts are flagged rather than dropped: an origin answering on a
    shared favicon behind CF is worth *seeing*, same reasoning as the VT
    hosting-history origin candidates.
    """
    if not key:
        return {}
    if limiter is not None:
        await limiter.wait()
    try:
        r = await client.get("https://api.shodan.io/shodan/host/search",
                            params={"key": key, "query": f"http.favicon.hash:{fhash}"},
                            timeout=25)
        if r.status_code != 200:
            return {}
        data = r.json()
        total = data.get("total") or 0
        if total > FAVICON_MAX_MATCHES:
            return {"skipped": total}
        out = []
        for m in data.get("matches", []):
            ip = m.get("ip_str")
            if not ip:
                continue
            ssl = m.get("ssl") or {}
            cert_cn = (((ssl.get("cert") or {}).get("subject") or {}).get("CN"))
            out.append({
                "ip": ip,
                "port": m.get("port"),
                "hostnames": sorted(m.get("hostnames") or []),
                "org": m.get("org"),
                "cert_cn": cert_cn,
                "title": (m.get("http") or {}).get("title") or m.get("title"),
                "in_cf": in_cf(ip, cf_nets),
            })
        return {"matches": out}
    except Exception:
        return {}



# --------------------------------------------------------------------------- #
# NVD CVE enrichment (CPE -> CVE, keyless, cached)
# --------------------------------------------------------------------------- #
def _cpe23(cpe: str) -> str:
    """Best-effort CPE 2.2 -> 2.3 for NVD virtualMatchString."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        body = cpe[5:]
        parts = body.split(":")
        parts += ["*"] * (11 - len(parts))
        return "cpe:2.3:" + ":".join(parts)
    return cpe


def _is_dos_only(vector: str | None) -> bool:
    """
    True if the CVSS vector's only impact is Availability — a classic DoS with no
    confidentiality/integrity impact. Not useful as an initial-access lead for a
    red team, so callers use this to drop it from entry-point consideration.
    Works for both v2 ("...C:N/I:N/A:C") and v3.x ("...C:N/I:N/A:H") vectors,
    since both use N for "None" on the C/I/A metrics.
    """
    if not vector:
        return False
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    return parts.get("A", "N") != "N" and parts.get("C", "N") == "N" and parts.get("I", "N") == "N"


def _parse_nvd_vuln(v: dict) -> dict:
    """Shared parser for one NVD `vulnerabilities[]` entry -> id/cvss/vector/desc/dos_only."""
    cve = v.get("cve", {})
    cid = cve.get("id")
    score = vector = None
    metrics = cve.get("metrics", {})
    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(mk):
            data = metrics[mk][0]["cvssData"]
            score = data.get("baseScore")
            vector = data.get("vectorString")
            break
    desc = next((d.get("value") for d in cve.get("descriptions", [])
                if d.get("lang") == "en"), None)
    if desc and len(desc) > 160:
        desc = desc[:160].rstrip() + "…"
    return {"id": cid, "cvss": score, "vector": vector, "desc": desc,
            "dos_only": _is_dos_only(vector)}


async def nvd_lookup(client, cpe: str, cache: dict, limiter) -> list:
    key = _cpe23(cpe)
    if key in cache:
        return cache[key]
    await limiter.wait()
    out = []
    try:
        r = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"virtualMatchString": key, "resultsPerPage": 20},
                            timeout=30)
        if r.status_code == 200:
            for v in r.json().get("vulnerabilities", []):
                parsed = _parse_nvd_vuln(v)
                if parsed["id"]:
                    out.append(parsed)
    except Exception:
        pass
    cache[key] = out
    return out


async def nvd_lookup_by_id(client, cve_id: str, cache: dict, limiter) -> dict | None:
    """
    Direct CVE-ID lookup — enriches bare IDs (e.g. Shodan/InternetDB `vulns` hits,
    which carry no CVSS/description on their own) with the same id/cvss/vector/desc/
    dos_only shape as nvd_lookup(), so they can be severity-ranked and DoS-filtered too.
    """
    if cve_id in cache:
        return cache[cve_id]
    await limiter.wait()
    out = None
    try:
        r = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"cveId": cve_id}, timeout=30)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                out = _parse_nvd_vuln(vulns[0])
    except Exception:
        pass
    cache[cve_id] = out
    return out


async def poc_lookup(client, cve_id: str, cache: dict, limiter) -> list | None:
    """
    Public PoC availability via nomi-sec/PoC-in-GitHub — a keyless aggregator
    that maintains one JSON file per CVE (<year>/<CVE-ID>.json) listing GitHub
    repos referencing it, with star counts. A 404 is the only authoritative
    "no known public PoC" signal — retry everything else (403/429/5xx,
    network errors) rather than treating it as absence, and don't cache a
    failure as []: doing so would permanently and silently suppress the
    PoC-aware severity bump for every host sharing that CVE for the rest of
    the run whenever GitHub's raw endpoint has a transient hiccup.
    Returns [{"url":..., "stars":...}, ...] sorted by stars desc, [] on a
    confirmed 404, or None if the lookup couldn't be completed.
    """
    if cve_id in cache:
        return cache[cve_id]
    parts = cve_id.split("-")
    year = parts[1] if len(parts) == 3 and parts[0] == "CVE" else None
    if not year:
        return None
    url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
    attempts = 3
    for attempt in range(attempts):
        await limiter.wait()
        try:
            r = await client.get(url, timeout=15)
            if r.status_code == 404:
                cache[cve_id] = []
                return []
            if r.status_code == 200:
                out = []
                for item in r.json():
                    repo_url = item.get("html_url")
                    if repo_url:
                        out.append({"url": repo_url, "stars": item.get("stargazers_count", 0)})
                out.sort(key=lambda p: -p["stars"])
                cache[cve_id] = out
                return out
            # non-200/404 (403/429/5xx) — transient, retry below
        except Exception:
            pass
        if attempt < attempts - 1:
            await asyncio.sleep(min(2 ** (attempt + 1), 10))
    return None            # gave up — left uncached, treated as unknown rather than "no PoC"


