from __future__ import annotations
import re

# --------------------------------------------------------------------------- #
# Lightweight tech fingerprinting (Wappalyzer-lite).
#
# host.tech used to be only Server + X-Powered-By, so confirm_tech_stack()
# almost never had anything to match a CVE's CPE against. This adds the cheap,
# high-signal fingerprints — meta generator, tell-tale headers/cookies, and a
# few body markers — for the server-side products a CVE is usually about
# (CMSes, frameworks), so tech-confirmation of the CVE section can actually fire.
#
# Pure and deterministic: fingerprint(headers, body, cookies) -> ["Product",
# "Product:version", ...]. Kept intentionally conservative — a false "WordPress"
# would wrongly confirm a WordPress CVE, so markers are specific, not generic
# library mentions (jQuery/React/Vue are deliberately absent).
# --------------------------------------------------------------------------- #

_META_GEN_RES = (
    re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I),
    re.compile(r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""", re.I),
)
_VER_RE = re.compile(r"(\d[\d.]*\d|\d)")


def _ver(s: str) -> str | None:
    m = _VER_RE.search(s or "")
    return m.group(1) if m else None


def _items(headers):
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers or [])


def fingerprint(headers, body: str = "", cookies=()) -> list:
    """Products served, as `["Product", "Product:version", ...]`.

    `headers` is a dict/mapping (or (k, v) pairs), `body` the HTML, `cookies`
    the response cookie names. Versions are attached when a source carries one
    (meta generator, `X-*-Version` headers), else the bare product name.
    """
    hdr = {(k or "").lower(): (v or "") for k, v in _items(headers)}
    body = body or ""
    lo = body.lower()
    ck = " ".join((c or "").lower() for c in (cookies or []))
    found: dict = {}                      # product -> version | None

    def mark(product, version=None):
        if product and (product not in found or (version and not found[product])):
            found[product] = version

    # --- meta generator: "WordPress 6.4.2", "Drupal 10 (https://…)" ---
    for gen in (m for rx in _META_GEN_RES for m in rx.findall(body)):
        g = gen.strip()
        m = re.match(r"([A-Za-z][A-Za-z0-9 ._-]*?)\s+v?(\d[\d.]*)", g)
        if m:
            mark(m.group(1).strip(), m.group(2))
        elif g:
            mark(g.split("(")[0].strip() or None)

    # --- headers ---
    if "drupal" in hdr.get("x-generator", "").lower():
        mark("Drupal", _ver(hdr["x-generator"]))
    if hdr.get("x-drupal-cache") or hdr.get("x-drupal-dynamic-cache"):
        mark("Drupal")
    if hdr.get("x-aspnet-version"):
        mark("ASP.NET", hdr["x-aspnet-version"])
    if hdr.get("x-shopify-stage") or hdr.get("x-shopid") or hdr.get("x-shardid"):
        mark("Shopify")
    # X-Powered-By (PHP/ASP.NET/Express/Next.js/…) is captured verbatim as a
    # base tech entry by the caller, so it is deliberately not re-parsed here —
    # doing so would just duplicate what http_probe already records.

    # --- cookies ---
    if "wordpress_" in ck or "wp-settings" in ck:
        mark("WordPress")
    if "laravel_session" in ck:
        mark("Laravel")
    if "csrftoken" in ck or "django" in ck:
        mark("Django")

    # --- body markers ---
    if "wp-content" in lo or "wp-includes" in lo:
        mark("WordPress")
    if "woocommerce" in lo:
        mark("WooCommerce")
    if "sites/default/files" in lo or "data-drupal-" in lo:
        mark("Drupal")
    if "/media/jui/" in lo or "com_content" in lo:
        mark("Joomla")
    if "__next_data__" in lo:
        mark("Next.js")
    if "__nuxt__" in lo or 'id="__nuxt"' in lo:
        mark("Nuxt")
    if "cdn.shopify.com" in lo or "shopify.theme" in lo:
        mark("Shopify")
    if "/mage/" in lo or "magento" in lo or "mage.cookies" in lo:
        mark("Magento")

    return [f"{p}:{v}" if v else p for p, v in found.items()]
