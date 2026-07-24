from __future__ import annotations
from datetime import datetime, timezone
from .common import *

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


async def vt_domain_intel(client, domain: str, api_key: str, limiter) -> dict:
    """Combined per-domain lookup — two calls against the shared rate limiter
    (VT free tier: 4 req/min). Returns {} if VT has nothing at all on the
    domain (neither a WHOIS/DNS snapshot nor any historical resolutions)."""
    await limiter.wait()
    info = await vt_domain_lookup(client, domain, api_key)
    await limiter.wait()
    history = await vt_ip_history(client, domain, api_key)
    if not info and not history:
        return {}
    info = dict(info)
    info["ip_history"] = history
    return info
