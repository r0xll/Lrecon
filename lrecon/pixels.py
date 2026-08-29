from __future__ import annotations
import re

# --------------------------------------------------------------------------- #
# Tracking-pixel / analytics ID extraction (keyless).
#
# A Google Analytics property, a GTM container, or a Facebook Pixel embedded on
# a page is an ownership fingerprint: two hosts sharing one are the same team's
# assets. We extract the IDs from the page body the HTTP probe already fetched
# and correlate them *within the scanned scope* — no third-party
# reverse-analytics lookup, so nothing about the target leaves the run.
# --------------------------------------------------------------------------- #

_PATTERNS = {
    # UA-XXXXXX-Y (Universal Analytics), G-XXXXXXXX (GA4), AW-… (Google Ads),
    # GT-… (Google Tag) — all Google analytics/marketing properties.
    "ga": re.compile(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|AW-\d{9,12}|GT-[A-Z0-9]{6,12})\b"),
    "gtm": re.compile(r"\b(GTM-[A-Z0-9]{5,8})\b"),
    # Facebook Pixel: fbq('init','<15-16 digit id>')
    "fb": re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,17})['"]"""),
}


def extract_tracking_ids(body: str) -> dict:
    """`{kind: [id, ...]}` for the analytics/marketing IDs present in `body`
    (GA/GA4/Ads/Tag, GTM, Facebook Pixel). Deduped, order preserved. Kinds with
    no hit are omitted, so an empty dict means a clean page."""
    out = {}
    for kind, rx in _PATTERNS.items():
        ids = list(dict.fromkeys(rx.findall(body or "")))
        if ids:
            out[kind] = ids
    return out
