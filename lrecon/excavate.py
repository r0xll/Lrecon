from __future__ import annotations
import re

# --------------------------------------------------------------------------- #
# Response mining for in-scope hostnames (BBOT excavate-style).
#
# Every page body, inline/linked JS, and a handful of response headers routinely
# name other subdomains the passive sources never returned — an API host in a
# fetch() call, a CDN/asset host in a CSP directive, a login host in a redirect.
# We mine the response the HTTP probe already fetched for FQDN-shaped strings and
# hand them back; core.run scope-filters them (name_in_scope) and wires the
# in-scope ones in as new hosts, the way cert SANs and rDNS names already are.
#
# This stays scope-agnostic and pure: it does not know the seed domains, so it
# cannot decide what is in scope — that is the caller's job, which keeps the
# regex simple and the function unit-testable. A file like `app.js` or a version
# like `1.2.3` may match the shape, but the scope filter drops anything that is
# not under a seed domain, and the final label must be alphabetic so bare version
# numbers never match here either.
# --------------------------------------------------------------------------- #

_HOST_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b")

# Response headers worth mining: they carry hostnames by design.
_HARVEST_HEADERS = (
    "content-security-policy", "content-security-policy-report-only",
    "access-control-allow-origin", "location", "report-to", "link",
    "x-pingback",
)


def extract_hostnames(text: str, headers=None) -> set:
    """Lowercased set of FQDN-shaped strings in `text` and selected response
    headers (CSP/CORS/Location/…). Scope filtering is the caller's job
    (name_in_scope) — this stays scope-agnostic and pure."""
    blob = text or ""
    if headers is not None:
        for h in _HARVEST_HEADERS:
            try:
                v = headers.get(h)
            except Exception:
                v = None
            if v:
                blob += "\n" + str(v)
    out = set()
    for m in _HOST_RE.finditer(blob):
        name = m.group(1).rstrip(".").lower()
        if len(name) <= 253:
            out.add(name)
    return out
