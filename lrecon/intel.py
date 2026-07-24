from __future__ import annotations
import asyncio, ipaddress, json
import httpx
from .common import *
from .sources import get_resolver, resolve_full
from .enrich import enrich_ipinfo

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
    Every candidate is also enriched with ASN/org (IPinfo, if a token is
    configured) so the report shows who actually hosts the leaked origin.

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

    # 5. ASN/org enrichment for each candidate IP — reuses the same IPinfo
    # enrichment path as in-scope hosts, so a client can immediately see
    # who actually hosts a leaked origin (own datacenter vs. a cloud
    # provider vs. another org's shared infrastructure).
    ipinfo_token = keys.get("ipinfo")
    if ipinfo_token and cands:
        for ip in list(cands):
            info = await enrich_ipinfo(client, ip, ipinfo_token)
            org = info.get("org")           # e.g. "AS15169 Google LLC"
            asn = org_name = None
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    asn, org_name = parts[0], (parts[1] if len(parts) > 1 else org)
                else:
                    org_name = org
            cands[ip]["asn"] = asn
            cands[ip]["org"] = org_name

    result["candidates"] = {ip: {"sources": sorted(v["sources"]),
                                 "confirmed": v["confirmed"], "evidence": v["evidence"],
                                 "asn": v.get("asn"), "org": v.get("org")}
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
# DNS records (A/AAAA/MX/NS/SOA) — apex-level snapshot for the report's own
# "DNS records" section. Distinct from resolve_full() (per-subdomain A/AAAA/
# CNAME used in Phase 2) and from email_security() above (which only surfaces
# the SPF/DMARC/DKIM TXT records, not the rest of the zone). A DNS query
# against the domain's own authoritative nameservers is the same "DNS only"
# touch tier as Phase 2 resolution, so this is gated the same way (not
# --passive-only), not run alongside the keyless RDAP/WHOIS lookup above.
# --------------------------------------------------------------------------- #
async def dns_lookup(domain: str, resolver_ns) -> dict:
    out = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "soa": None}
    if not _HAVE_DNS:
        return out
    res = get_resolver(resolver_ns)

    async def q(rtype):
        try:
            return await res.resolve(domain, rtype)
        except Exception:
            return None

    a, aaaa, mx, nsrr, txt, soa = await asyncio.gather(
        q("A"), q("AAAA"), q("MX"), q("NS"), q("TXT"), q("SOA"))
    if a:
        out["a"] = sorted(str(r) for r in a)
    if aaaa:
        out["aaaa"] = sorted(str(r) for r in aaaa)
    if mx:
        out["mx"] = sorted(({"priority": r.preference, "host": str(r.exchange).rstrip(".").lower()}
                            for r in mx), key=lambda m: m["priority"])
    if nsrr:
        out["ns"] = sorted(str(r).rstrip(".").lower() for r in nsrr)
    if txt:
        out["txt"] = ["".join(s.decode(errors="ignore") for s in r.strings) for r in txt]
    if soa:
        out["soa"] = str(soa[0].mname).rstrip(".").lower()
    return out



# --------------------------------------------------------------------------- #
# Mail infrastructure identification — resolves each MX host's IP and
# enriches it via IPinfo (ASN/org/country, reusing the same enrichment used
# for in-scope hosts), then labels well-known managed-email providers by
# hostname so the report reads "Google Workspace" / "Microsoft 365" rather
# than an opaque MX hostname. One entry per unique MX host — several
# priority tiers commonly share a provider's pool (e.g. multiple
# *.protection.outlook.com records).
# --------------------------------------------------------------------------- #
MAIL_PROVIDER_PATTERNS = [
    ("Google Workspace",               ["google.com", "googlemail.com"]),
    ("Microsoft 365",                  ["outlook.com", "protection.outlook.com"]),
    ("Proofpoint",                     ["pphosted.com", "proofpoint.com"]),
    ("Mimecast",                       ["mimecast.com"]),
    ("Barracuda",                      ["barracudanetworks.com"]),
    ("Cisco Secure Email (IronPort)",  ["iphmx.com", "ppe-hosted.com"]),
    ("Zoho Mail",                      ["zoho.com", "zohomail.com"]),
    ("Amazon SES / WorkMail",          ["amazonaws.com", "awsapps.com"]),
    ("Yandex Mail",                    ["yandex.net", "yandex.ru"]),
]


def _classify_mail_provider(mx_host: str) -> str | None:
    h = mx_host.lower()
    for name, patterns in MAIL_PROVIDER_PATTERNS:
        if any(p in h for p in patterns):
            return name
    return None


async def mail_infra_lookup(client, mx_records: list, ipinfo_token: str | None, resolver_ns) -> list:
    out = []
    seen = set()
    for mx in mx_records:
        host = mx["host"]
        if host in seen:
            continue
        seen.add(host)
        entry = {"host": host, "priority": mx["priority"], "ips": [],
                 "provider": _classify_mail_provider(host), "asn": None, "org": None, "country": None}
        if _HAVE_DNS:
            try:
                res = get_resolver(resolver_ns)
                entry["ips"] = sorted(str(r) for r in await res.resolve(host, "A"))
            except Exception:
                pass
        if entry["ips"] and ipinfo_token:
            info = await enrich_ipinfo(client, entry["ips"][0], ipinfo_token)
            org = info.get("org")           # e.g. "AS15169 Google LLC"
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    entry["asn"] = parts[0]
                    entry["org"] = parts[1] if len(parts) > 1 else org
                else:
                    entry["org"] = org
            entry["country"] = info.get("country")
        out.append(entry)
    return out



# --------------------------------------------------------------------------- #
# Domain registration data (WHOIS via RDAP) — keyless, third-party registry
# only, never touches the target's own infrastructure. RDAP is the
# structured, JSON-based successor to WHOIS; rdap.org is a public bootstrap
# redirector to the authoritative RDAP server for whatever TLD the domain is
# under, so one endpoint covers the large majority of TLDs without needing to
# chase IANA referrals ourselves.
#
# rdap.org routes to the REGISTRY's RDAP server (e.g. Verisign for .com,
# PIR for .org), which — post-GDPR — omits registrant data entirely for
# most gTLDs; that data instead lives at the REGISTRAR's own RDAP server,
# referenced by a `rel=related` link in the registry response. rdap_lookup()
# follows that one extra hop when the registry response has no registrant
# entity, since that's what actually surfaces privacy-protection status for
# the common case (confirmed live: registry-level namecheap.com has no
# registrant entity at all; the registrar-level referral shows
# rdapConformance containing "redacted" plus a registrant vcard org of
# "Privacy service provided by Withheld for Privacy ehf").
# --------------------------------------------------------------------------- #
_PRIVACY_KEYWORDS = ("privacy", "proxy", "redacted", "withheld", "protect", "whoisguard")


def _rdap_vcard_field(entity: dict, field: str) -> str | None:
    """A jCard field (vcardArray[1] is a list of [field, params, type, value, ...]
    entries) — e.g. "fn" (name) or "org" (organization, often where a privacy
    service's own name shows up for a redacted registrant)."""
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] == field and item[3]:
            return item[3]
    return None


def _rdap_entity_name(entity: dict) -> str | None:
    return _rdap_vcard_field(entity, "fn")


def _rdap_referral_link(data: dict) -> str | None:
    """The registrar's own RDAP endpoint, if the registry response links to one."""
    for link in data.get("links", []) or []:
        if link.get("rel") == "related" and "rdap" in (link.get("type") or "").lower():
            return link.get("href")
    return None


def _parse_rdap(data: dict) -> dict:
    out = {"registrar": None, "created": None, "expires": None,
          "last_changed": None, "nameservers": [], "status": [],
          "registrant_name": None, "registrant_org": None,
          "privacy_protected": None, "privacy_provider": None}
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

    registrant = next((e for e in data.get("entities", []) or [] if "registrant" in (e.get("roles") or [])),
                      None)
    if registrant:
        name = _rdap_entity_name(registrant)
        org = _rdap_vcard_field(registrant, "org")
        out["registrant_name"] = name
        out["registrant_org"] = org
        redacted_ext = bool(data.get("redacted")) or "redacted" in (data.get("rdapConformance") or [])
        looks_private = any(k in (org or "").lower() for k in _PRIVACY_KEYWORDS) or \
                        any(k in (name or "").lower() for k in _PRIVACY_KEYWORDS)
        if redacted_ext or looks_private or not name:
            out["privacy_protected"] = True
            out["privacy_provider"] = org if (org and looks_private) else None
        else:
            out["privacy_protected"] = False
    return out


async def rdap_lookup(client, domain: str) -> dict:
    """
    Overrides the shared client's default follow_redirects=False for this one
    call — rdap.org responds with a redirect to the authoritative registry
    (e.g. rdap.verisign.com for .com), confirmed live against example.com.
    Returns {} on any failure — many domains (some ccTLDs without RDAP
    support yet, typos, internal-only names) simply won't resolve. Still
    logged (once, at "no data" level) rather than silently vanishing, since
    a fully-empty WHOIS section with no explanation is confusing — the
    caller shows a placeholder row for the domain either way.

    If the registry response has no registrant entity (the common case for
    thin gTLD registries), follows the registrar's own RDAP referral link
    once to fill in registrant/privacy-protection fields — best-effort, a
    failed or missing referral just leaves those fields as "unknown" rather
    than failing the whole lookup.
    """
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", timeout=20, follow_redirects=True)
        if r.status_code != 200:
            log(f"[!] whois/rdap {domain}: no data (HTTP {r.status_code} from rdap.org)")
            return {}
        data = r.json()
        out = _parse_rdap(data)
        if out["registrant_name"] is None and out["registrant_org"] is None \
                and out["privacy_protected"] is None:
            referral = _rdap_referral_link(data)
            if referral:
                try:
                    r2 = await client.get(referral, timeout=20, follow_redirects=True)
                    if r2.status_code == 200:
                        ref = _parse_rdap(r2.json())
                        for k in ("registrant_name", "registrant_org",
                                 "privacy_protected", "privacy_provider"):
                            out[k] = ref[k]
                        for k in ("registrar", "created", "expires", "last_changed"):
                            out[k] = out[k] or ref[k]
                        out["nameservers"] = out["nameservers"] or ref["nameservers"]
                        out["status"] = out["status"] or ref["status"]
                except Exception:
                    pass   # referral hop is best-effort; registry data still returned
        return out
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
        # Cross-references the reported CPEs against the live tech-detect
        # probe (enrich.confirm_tech_stack) — Shodan/InternetDB data can be
        # weeks stale, so this flags whether the vulnerable software still
        # looks live, to cut down manual triage.
        tech_note = " [tech-stack confirmed live]" if h.tech_confirmed is True else \
                    (" [unconfirmed — live probe found no matching software, may be stale]"
                     if h.tech_confirmed is False else "")
        detail = "; ".join(
            cid + (f" (CVSS {nvd_by_id[cid]['cvss']})" if nvd_by_id.get(cid, {}).get("cvss") is not None else "")
            + (" [PoC]" if nvd_by_id.get(cid, {}).get("poc") else "")
            + (f" — {nvd_by_id[cid]['desc']}" if nvd_by_id.get(cid, {}).get("desc") else "")
            for cid in ranked[:known_cve_cap])
        if len(ranked) > known_cve_cap:
            detail += f"; +{len(ranked) - known_cve_cap} more"
        out.append({"type": "known-cve", "target": h.subdomain,
                   "severity": severity,
                   "summary": f"{len(ranked)} known CVE(s){cvss_note}{poc_note}{dos_note}"
                              f"{unscored_note}{tech_note}: {detail}",
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

