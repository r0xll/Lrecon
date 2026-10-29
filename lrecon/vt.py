from __future__ import annotations
from datetime import datetime, timezone
from .common import *
from .enrich import enrich_ipinfo
from .intel import in_cf
from .cache import cached

# --------------------------------------------------------------------------- #
# VirusTotal domain intelligence — historical domain->IP resolutions ("hosting
# history") plus VT's own WHOIS mirror, DNS-record snapshot, and reputation/
# detection stats, via VirusTotal's official public API v3. Free API key, no
# cost — the closest free equivalent to a DomainTools-style history lookup.
#
# The free tier is rate-limited to 4 requests/minute (500/day), and each
# domain costs two calls (domain info + resolutions), so this is opt-in via
# --vt even with a key configured — auto-running it on every scope would add
# real wall-clock time (up to ~30s/domain) to a run the user didn't
# necessarily want it in, the same reasoning as --dork/--nvd/--buckets.
# --------------------------------------------------------------------------- #
def _unix_to_iso(ts) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _parse_vt_domain(data: dict) -> dict:
    attrs = (data or {}).get("data", {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "reputation": attrs.get("reputation"),
        "creation_date": _unix_to_iso(attrs.get("creation_date")),
        "last_modification_date": _unix_to_iso(attrs.get("last_modification_date")),
        "whois": attrs.get("whois"),
        "whois_date": _unix_to_iso(attrs.get("whois_date")),
        "categories": attrs.get("categories") or {},
        "last_dns_records": [{"type": r.get("type"), "value": r.get("value")}
                             for r in (attrs.get("last_dns_records") or [])],
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
    }


def _parse_vt_resolutions(data: dict) -> list:
    out = []
    for item in (data or {}).get("data", []) or []:
        attrs = item.get("attributes", {}) or {}
        ip = attrs.get("ip_address")
        if not ip:
            continue
        out.append({"ip": ip, "first_seen": _unix_to_iso(attrs.get("date"))})
    out.sort(key=lambda r: r.get("first_seen") or "", reverse=True)
    return out


async def vt_domain_lookup(client, domain: str, api_key: str) -> dict:
    """VT's own domain snapshot: WHOIS mirror, cached DNS records, reputation/
    detection stats. Returns {} on failure/no data — a domain VT hasn't seen
    yet is expected, not an error worth logging loudly."""
    headers = {"x-apikey": api_key}
    try:
        r = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                            headers=headers, timeout=20)
        if r.status_code == 200:
            return _parse_vt_domain(r.json())
        if r.status_code == 401:
            log("[!] VirusTotal API: invalid key")
        elif r.status_code == 429:
            log(f"[!] VirusTotal {domain}: rate limited (429) — skipping")
    except Exception as e:
        log(f"[!] VirusTotal {domain}: {e}")
    return {}


async def vt_ip_history(client, domain: str, api_key: str, limit: int = 20) -> list:
    """Historical domain->IP passive-DNS resolutions VT has observed, newest
    first — the closest free equivalent to DomainTools' hosting history."""
    headers = {"x-apikey": api_key}
    try:
        r = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
                            headers=headers, params={"limit": limit}, timeout=20)
        if r.status_code == 200:
            return _parse_vt_resolutions(r.json())
        if r.status_code == 429:
            log(f"[!] VirusTotal {domain}: rate limited (429) on IP history — skipping")
    except Exception as e:
        log(f"[!] VirusTotal {domain} IP history: {e}")
    return []


async def enrich_ip_history(client, vt_intel: dict, ipinfo_token, cf_nets,
                            live_by_domain: dict | None = None) -> int:
    """Attach ASN/org/country to each historical IP, and mark origin candidates.

    A bare list of past IPs and dates is close to unusable on an engagement: it
    says a domain moved, not what it moved between. One IPinfo lookup per unique
    address turns each row into "who hosted it", which is what makes a hosting
    history worth reading — a former colo or cloud tenancy is a very different
    story from a former CDN.

    The red-team payload is `origin_candidate`: an address the domain used to
    answer on directly while it is *now* behind Cloudflare — a plausible
    unproxied origin, the same thing the CF-origin phase hunts for, reached
    through passive history instead of active probing. It is a lead to verify by
    fetching the IP with the target's Host header, not a conclusion; a shared
    host or a long-since-reassigned cloud address looks identical here.

    Three conditions all have to hold, and each one is load-bearing:

      * **the domain is Cloudflare-fronted today** — decided per domain from its
        own live IPs. Without this every past address of an unproxied domain
        becomes an "origin", which is just a hosting change with a scary label;
      * **the historical address is not itself Cloudflare** — otherwise it is
        the CDN, not what sits behind it;
      * **it is not still live for that same domain** — checked against that
        domain's own addresses, because in a multi-domain scope a shared IP
        would otherwise let one domain's live set hide another's stale record.

    When a domain has no live IPs — `--passive-only` skips resolution entirely —
    its fronted state is unknown, and nothing is flagged. Each domain records
    which of those it was in `origin_check` so the report can say why the column
    is empty instead of implying a clean result.

    Lookups are deduped across domains, so a domain that never moved off one
    address costs one call. Returns the number of IPs enriched.
    """
    rows = [r for v in vt_intel.values() for r in (v.get("ip_history") or [])]
    unique = sorted({r["ip"] for r in rows if r.get("ip")})
    if not unique:
        return 0
    infos = await asyncio.gather(*(enrich_ipinfo(client, ip, ipinfo_token) for ip in unique))
    by_ip = dict(zip(unique, infos))
    nets = _cf_nets(cf_nets)
    for domain, v in vt_intel.items():
        live = set((live_by_domain or {}).get(domain) or ())
        fronted = any(in_cf(ip, nets) for ip in live)
        v["origin_check"] = ("fronted" if fronted else
                             "not_fronted" if live else "unknown")
        for r in (v.get("ip_history") or []):
            data = by_ip.get(r.get("ip")) or {}
            r["asn"], r["org"] = _ipinfo_asn_org(data)
            r["country"] = data.get("country")
            r["rdns"] = data.get("hostname")
            behind_cf = in_cf(r["ip"], nets)
            r["cloudflare"] = behind_cf
            r["origin_candidate"] = bool(fronted and not behind_cf and r["ip"] not in live)
    return len(unique)


def _cf_nets(cf_nets) -> list:
    """Cloudflare ranges as network objects, falling back to the bundled list.

    `--passive-only` and `--no-cf-origin` skip the live range fetch, leaving
    `cf_nets` empty — and with no ranges every historical address would be
    labelled an origin candidate, including the ones plainly behind the CDN.
    Also accepts CIDR strings so callers don't have to care which they hold.
    """
    out = []
    for n in (cf_nets or CF_FALLBACK):
        try:
            out.append(n if hasattr(n, "network_address") else ipaddress.ip_network(n))
        except Exception:
            pass
    return out


def _ipinfo_asn_org(data: dict) -> tuple:
    """(asn, org) out of an IPinfo payload, whichever shape it came back in.

    Free/keyless responses put "AS13335 Cloudflare, Inc." in `org`; token
    responses split it into an `asn` object. apply_ipinfo() already handles both
    for live hosts — this mirrors it rather than assuming the keyed shape, since
    keyless is the common case.
    """
    asn_obj = data.get("asn") or {}
    if isinstance(asn_obj, dict) and asn_obj.get("asn"):
        return asn_obj.get("asn"), asn_obj.get("name") or data.get("org")
    org = data.get("org") or ""
    if org.startswith("AS"):
        num, _, name = org.partition(" ")
        return num, name or None
    return None, org or None


async def vt_domain_intel(client, domain: str, api_key: str, limiter) -> dict:
    """Combined per-domain lookup — two calls against the shared rate limiter
    (VT free tier: 4 req/min). Returns {} if VT has nothing at all on the
    domain (neither a WHOIS/DNS snapshot nor any historical resolutions).
    Disk-cached per domain — the rate-limited two-call lookup is a prime
    repeat-run cost."""
    async def _fetch():
        await limiter.wait()
        info = await vt_domain_lookup(client, domain, api_key)
        await limiter.wait()
        history = await vt_ip_history(client, domain, api_key)
        if not info and not history:
            return {}
        info = dict(info)
        info["ip_history"] = history
        return info
    return await cached("vt", domain, _fetch)
