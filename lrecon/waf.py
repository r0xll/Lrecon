from __future__ import annotations
from .common import in_cf

# --------------------------------------------------------------------------- #
# WAF / CDN fingerprinting.
#
# Only Cloudflare was ever detected (by IP range, for the origin hunt). Add the
# other major CDNs/WAFs from their tell-tale response headers, so the report
# says what's fronting each host — context for triage and for judging whether a
# CVE/entry point is actually reachable or sits behind a WAF. Detection only;
# origin-hunting stays Cloudflare-specific for now.
# --------------------------------------------------------------------------- #


def _items(headers):
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers or [])


def fingerprint_waf(headers, ip: str | None = None, cf_nets=None) -> str | None:
    """The CDN/WAF fronting a response, or None. Header-based (primary) with a
    Cloudflare IP-range fallback."""
    hdr = {(k or "").lower(): (v or "").lower() for k, v in _items(headers)}
    server = hdr.get("server", "")
    via = hdr.get("via", "")
    set_cookie = hdr.get("set-cookie", "")

    if "cf-ray" in hdr or "cloudflare" in server or "cloudflare" in via:
        return "Cloudflare"
    if any(k.startswith("x-akamai") for k in hdr) or "akamaighost" in server or "akamai" in via:
        return "Akamai"
    if "x-amz-cf-id" in hdr or "cloudfront" in via or "cloudfront" in server:
        return "CloudFront"
    if any(k.startswith("fastly") for k in hdr) or ("x-served-by" in hdr and "varnish" in via):
        return "Fastly"
    if "x-iinfo" in hdr or "incap_ses" in set_cookie or "incapsula" in server:
        return "Imperva Incapsula"
    if "x-sucuri-id" in hdr or "x-sucuri-cache" in hdr or "sucuri" in server:
        return "Sucuri"
    # IP-range fallback: Cloudflare fronts without cf-ray on some error paths.
    if ip and cf_nets and in_cf(ip, cf_nets):
        return "Cloudflare"
    return None
