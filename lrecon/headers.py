from __future__ import annotations
import re

# --------------------------------------------------------------------------- #
# HTTP security-header + cookie-flag audit.
#
# The probe recorded status/server/title and nothing about the response's
# security posture. Capture the high-value headers (CSP, HSTS, X-Frame-Options,
# X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and cookie flags
# (Secure/HttpOnly/SameSite), then report the gaps. These are hardening gaps,
# not initial-access vectors, so they live in their own report section rather
# than the entry-point list.
# --------------------------------------------------------------------------- #


def _items(headers):
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers or [])


def security_headers(headers, set_cookies=()) -> dict:
    """Structured security posture of a response: header presence/values and
    per-cookie flags. Pure and case-insensitive."""
    hdr = {(k or "").lower(): (v or "") for k, v in _items(headers)}

    hsts_raw = hdr.get("strict-transport-security", "")
    hsts = None
    if hsts_raw:
        m = re.search(r"max-age=(\d+)", hsts_raw, re.I)
        low = hsts_raw.lower()
        hsts = {"max_age": int(m.group(1)) if m else None,
                "include_subdomains": "includesubdomains" in low.replace(" ", ""),
                "preload": "preload" in low}

    cookies = []
    for c in set_cookies or []:
        if not c:
            continue
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        m = re.search(r"samesite=(\w+)", low)
        cookies.append({"name": name, "secure": "secure" in low,
                        "httponly": "httponly" in low,
                        "samesite": m.group(1) if m else None})

    return {
        "csp": hdr.get("content-security-policy") or None,
        "hsts": hsts,
        "x_frame_options": hdr.get("x-frame-options") or None,
        "x_content_type_options": hdr.get("x-content-type-options") or None,
        "referrer_policy": hdr.get("referrer-policy") or None,
        "permissions_policy": hdr.get("permissions-policy") or None,
        "cookies": cookies,
    }


def header_gaps(sec: dict, scheme: str = "https") -> list:
    """Missing high-value protections, as short human-readable strings."""
    if not sec:
        return []
    gaps = []
    if scheme == "https" and not sec.get("hsts"):
        gaps.append("no HSTS")
    if not sec.get("csp"):
        gaps.append("no CSP")
    if not sec.get("x_content_type_options"):
        gaps.append("no X-Content-Type-Options")
    # A CSP frame-ancestors directive supersedes X-Frame-Options — only flag
    # clickjacking exposure when neither is present.
    if not sec.get("x_frame_options") and not sec.get("csp"):
        gaps.append("no X-Frame-Options / frame-ancestors")
    if not sec.get("referrer_policy"):
        gaps.append("no Referrer-Policy")
    if not sec.get("permissions_policy"):
        gaps.append("no Permissions-Policy")
    for c in sec.get("cookies", []):
        missing = [f for f in ("secure", "httponly") if not c.get(f)]
        if missing:
            gaps.append(f"cookie '{c['name']}' missing {'/'.join(missing)}")
    return gaps
