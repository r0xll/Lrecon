from __future__ import annotations
from .common import *

# --------------------------------------------------------------------------- #
# Search-engine dorking (Google Custom Search JSON API) — finds exposed
# admin/login panels, config/env files, directory listings, .git/backup
# leaks, etc. via `site:` dorks. Uses Google's official, keyed, ToS-compliant
# Custom Search API — deliberately NOT raw Google/DuckDuckGo HTML scraping,
# which would carry the same ToS/reliability risk already ruled out for
# LinkedIn scraping in people.py (defeating anti-automation measures on a
# platform whose terms prohibit it, rather than using an approved API).
#
# The free tier is 100 queries/day total across every domain and category,
# so this is opt-in via --dork even when a key is configured (unlike the
# lower-cost People OSINT sources, which auto-run on key presence) — a run
# against a few domains can otherwise burn the whole day's quota without the
# user asking for it.
# --------------------------------------------------------------------------- #
DORK_TEMPLATES = [
    # (category, query, severity) — kept deliberately small given the quota.
    ("admin-panel", "inurl:admin OR inurl:login OR inurl:signin", "medium"),
    ("config-exposure", "filetype:env OR filetype:ini OR intext:\"DB_PASSWORD\"", "high"),
    ("directory-listing", "intitle:\"index of\"", "medium"),
    ("backup-exposure", "filetype:sql OR filetype:bak OR filetype:backup", "high"),
    ("git-exposure", "inurl:.git", "high"),
    ("api-docs", "inurl:swagger OR inurl:api-docs OR inurl:api/v1", "medium"),
    ("debug-page", "intext:\"stack trace\" OR intext:\"fatal error\" OR intext:\"debug mode\"", "medium"),
]


def _parse_cse_response(data: dict) -> list:
    out = []
    for item in (data or {}).get("items", []) or []:
        link = item.get("link")
        if not link:
            continue
        out.append({"title": item.get("title") or "", "link": link,
                   "snippet": item.get("snippet") or ""})
    return out


async def google_dork(client, domain: str, api_key: str, cx: str, limiter) -> tuple:
    """
    Returns (hits, terminal). terminal=True means the response indicated a
    condition that will recur identically for every remaining domain (quota
    exhausted, invalid key, invalid cx) — the caller should stop querying
    entirely rather than burning the shared rate limiter on doomed requests
    for the rest of the domain list. A transient per-request exception is
    NOT treated as terminal (it only aborts this domain's remaining
    categories) since it doesn't necessarily indicate the same failure would
    repeat for other domains.

    Uses the API's siteSearch/siteSearchFilter params, not a `site:{domain}`
    prefix folded into the free-text query — several DORK_TEMPLATES entries
    contain top-level `OR`, and Google's query-syntax precedence only binds
    a leading `site:` to the first OR branch, letting later branches (e.g.
    `inurl:login` on its own) match pages on any indexed site, not just the
    scoped domain. siteSearch/siteSearchFilter constrain the whole query
    regardless of its internal OR/AND structure.
    """
    seen_links = set()
    out = []
    terminal = False
    for category, query, severity in DORK_TEMPLATES:
        await limiter.wait()
        try:
            r = await client.get("https://www.googleapis.com/customsearch/v1",
                                params={"key": api_key, "cx": cx, "q": query,
                                        "siteSearch": domain, "siteSearchFilter": "i"},
                                timeout=25)
            if r.status_code == 200:
                for hit in _parse_cse_response(r.json()):
                    if hit["link"] in seen_links:
                        continue
                    seen_links.add(hit["link"])
                    out.append({**hit, "category": category, "severity": severity})
            elif r.status_code == 403:
                log("[!] google dork: quota exhausted or key/cx invalid — stopping")
                terminal = True
                break
            elif r.status_code == 400:
                log("[!] google dork: bad request (check --google-cse-key/--google-cse-cx)")
                terminal = True
                break
        except Exception as e:
            log(f"[!] google dork {domain}: {e}")
            break
    return out, terminal
