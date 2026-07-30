from __future__ import annotations
from urllib.parse import urlparse
from .common import *

# --------------------------------------------------------------------------- #
# Search-engine dorking — finds exposed admin/login panels, config/env files,
# directory listings, .git/backup leaks, etc. via `site:` dorks. Every backend
# is an official, keyed, ToS-compliant search API — deliberately NOT raw
# Google/DuckDuckGo HTML scraping, which would carry the same ToS/reliability
# risk already ruled out for LinkedIn scraping in people.py (defeating
# anti-automation measures on a platform whose terms prohibit it, rather than
# using an approved API).
#
# Three interchangeable backends, auto-selected from whichever credentials are
# configured (override with --dork-provider):
#
#   * google — Google Custom Search JSON API. **Closed to new customers** as of
#     2025 (existing key-holders keep working); kept as the default when a
#     CSE key+cx is already configured.
#   * brave  — Brave Search API. The easiest replacement to obtain: a free
#     self-serve signup, a single API key, a plain REST endpoint, and native
#     `site:` support. The recommended backend for new users.
#   * vertex — Google Vertex AI Search (Discovery Engine). Google's official
#     successor to CSE for site-restricted search (up to 50 domains per data
#     store). Needs a GCP project + a Search app/data store + an OAuth access
#     token (e.g. `gcloud auth print-access-token`) — no service-account SDK
#     is pulled in, keeping the dependency set minimal.
#
# Dorking is opt-in via --dork even when a key is configured (unlike the
# lower-cost People OSINT sources, which auto-run on key presence): the free
# quotas are tight (Google CSE 100 queries/day, Brave 2k/month) and a run
# against a few domains can otherwise burn the whole allowance without the
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


# --------------------------------------------------------------------------- #
# Scope filter — shared by the backends that can't constrain results to the
# target domain at the API level the way Google CSE's siteSearchFilter does.
# Several DORK_TEMPLATES entries contain a top-level `OR`, and folding a
# leading `site:{domain}` into such a query only binds to the first OR branch,
# letting later branches match pages on any indexed site. Rather than rely on
# each engine's query-operator precedence, results are post-filtered by their
# link's host so scoping is provably correct regardless of the query shape.
# --------------------------------------------------------------------------- #
def _in_scope(link: str, domain: str) -> bool:
    try:
        host = (urlparse(link).hostname or "").lower()
    except Exception:
        return False
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def _scoped(hits: list, domain: str) -> list:
    return [h for h in hits if _in_scope(h["link"], domain)]


async def _run_templates(domain: str, limiter, search_one) -> tuple:
    """Drive the DORK_TEMPLATES loop for a backend. `search_one(query)` runs a
    single search and returns (hits, terminal); a raised exception aborts only
    this domain's remaining categories (non-terminal, matching google_dork's
    per-request exception semantics). Dedupe/category/severity tagging is
    identical to google_dork's."""
    seen_links = set()
    out = []
    terminal = False
    for category, query, severity in DORK_TEMPLATES:
        await limiter.wait()
        try:
            hits, terminal = await search_one(query)
        except Exception as e:
            log(f"[!] dork {domain}: {e}")
            break
        for hit in (hits or []):
            if hit["link"] in seen_links:
                continue
            seen_links.add(hit["link"])
            out.append({**hit, "category": category, "severity": severity})
        if terminal:
            break
    return out, terminal


# --------------------------------------------------------------------------- #
# Brave Search API — GET, single API key in the X-Subscription-Token header.
# --------------------------------------------------------------------------- #
def _parse_brave_response(data: dict) -> list:
    out = []
    for item in ((data or {}).get("web") or {}).get("results", []) or []:
        link = item.get("url")
        if not link:
            continue
        out.append({"title": item.get("title") or "", "link": link,
                   "snippet": item.get("description") or ""})
    return out


async def brave_dork(client, domain: str, api_key: str, limiter) -> tuple:
    """Returns (hits, terminal). terminal=True on a condition that will recur
    identically for every remaining domain (invalid key, quota/rate exhausted,
    malformed request), so the caller stops entirely — same contract as
    google_dork()."""
    async def search_one(query):
        r = await client.get("https://api.search.brave.com/res/v1/web/search",
                            params={"q": f"site:{domain} {query}", "count": 10},
                            headers={"X-Subscription-Token": api_key,
                                     "Accept": "application/json"},
                            timeout=25)
        if r.status_code == 200:
            return _scoped(_parse_brave_response(r.json()), domain), False
        if r.status_code in (401, 403):
            log("[!] brave dork: key invalid or unauthorized — stopping")
            return [], True
        if r.status_code == 429:
            log("[!] brave dork: rate limit / monthly quota exhausted — stopping")
            return [], True
        if r.status_code in (400, 422):
            log("[!] brave dork: bad request — stopping")
            return [], True
        return [], False
    return await _run_templates(domain, limiter, search_one)


# --------------------------------------------------------------------------- #
# Google Vertex AI Search (Discovery Engine) — POST to a servingConfig's
# :search endpoint with an OAuth bearer token. The website data store is
# already scoped to the operator's configured domains; `site:{domain}` narrows
# to the specific target among them, and the host post-filter guarantees scope.
# --------------------------------------------------------------------------- #
def _parse_vertex_response(data: dict) -> list:
    out = []
    for res in (data or {}).get("results", []) or []:
        doc = (res.get("document") or {}).get("derivedStructData") or {}
        link = doc.get("link")
        if not link:
            continue
        snippet = ""
        snips = doc.get("snippets") or []
        if isinstance(snips, list) and snips:
            snippet = (snips[0] or {}).get("snippet") or ""
        snippet = snippet or doc.get("htmlSnippet") or ""
        out.append({"title": doc.get("title") or "", "link": link, "snippet": snippet})
    return out


def _vertex_search_url(creds: dict) -> str | None:
    project = creds.get("project")
    location = creds.get("location") or "global"
    if not project:
        return None
    base = (f"https://discoveryengine.googleapis.com/v1/projects/{project}"
            f"/locations/{location}/collections/default_collection")
    if creds.get("engine"):
        return f"{base}/engines/{creds['engine']}/servingConfigs/default_search:search"
    if creds.get("datastore"):
        return f"{base}/dataStores/{creds['datastore']}/servingConfigs/default_search:search"
    return None


async def vertex_dork(client, domain: str, creds: dict, limiter) -> tuple:
    """Returns (hits, terminal). `creds` carries access_token, project,
    location, and engine or datastore. terminal=True on auth/permission/quota/
    config errors that would repeat for every domain — same contract as
    google_dork()."""
    url = _vertex_search_url(creds)
    if not url or not creds.get("access_token"):
        log("[!] vertex dork: incomplete config (need access token, project, engine/datastore)")
        return [], True

    async def search_one(query):
        r = await client.post(url,
                             json={"query": f"site:{domain} {query}", "pageSize": 10},
                             headers={"Authorization": f"Bearer {creds['access_token']}",
                                      "Content-Type": "application/json"},
                             timeout=25)
        if r.status_code == 200:
            return _scoped(_parse_vertex_response(r.json()), domain), False
        if r.status_code in (401, 403):
            log("[!] vertex dork: token invalid/expired or insufficient IAM — stopping")
            return [], True
        if r.status_code == 429:
            log("[!] vertex dork: quota exhausted — stopping")
            return [], True
        if r.status_code in (400, 404):
            log("[!] vertex dork: bad request or engine/data-store not found — stopping")
            return [], True
        return [], False
    return await _run_templates(domain, limiter, search_one)


# --------------------------------------------------------------------------- #
# Backend selection + unified per-domain entry point.
# --------------------------------------------------------------------------- #
def _vertex_ready(creds) -> bool:
    creds = creds or {}
    return bool(creds.get("access_token") and creds.get("project")
                and (creds.get("engine") or creds.get("datastore")))


DORK_PROVIDER_ORDER = ("google", "brave", "vertex")


def configured_dork_providers(keys: dict, requested: str | None = "auto") -> list:
    """Every usable dork backend, in the order they should be tried.

    `auto`/None returns all configured backends, preferring Google CSE so
    existing key-holders keep their current behavior, then Brave, then Vertex.
    An explicit `requested` provider returns just that one, and only if its
    credentials are actually present (else `[]`, so the caller reports "not
    configured") — pinning a backend must never silently fall back to another.

    The list matters because a backend can fail *terminally* mid-run (revoked
    key, exhausted quota): Google CSE is closed to new customers, so a stale CSE
    key alongside a working Brave key is a realistic setup, and without a
    fallback chain the run would produce nothing.
    """
    ready = {
        "google": bool(keys.get("google_cse") and keys.get("google_cse_cx")),
        "brave": bool(keys.get("brave")),
        "vertex": _vertex_ready(keys.get("vertex")),
    }
    if requested and requested != "auto":
        return [requested] if ready.get(requested) else []
    return [name for name in DORK_PROVIDER_ORDER if ready[name]]


def select_dork_provider(keys: dict, requested: str | None = "auto") -> str | None:
    """The backend a run starts with, or None if nothing is configured. Thin
    wrapper over configured_dork_providers() so there's one source of truth;
    used for the startup log line and by callers that only need the first."""
    return next(iter(configured_dork_providers(keys, requested)), None)


async def dork_domain(client, domain: str, provider: str, keys: dict, limiter) -> tuple:
    """Dispatch one domain's dork sweep to the selected backend. Returns
    (hits, terminal) — the same contract every backend honors."""
    if provider == "google":
        return await google_dork(client, domain, keys["google_cse"],
                                 keys["google_cse_cx"], limiter)
    if provider == "brave":
        return await brave_dork(client, domain, keys["brave"], limiter)
    if provider == "vertex":
        return await vertex_dork(client, domain, keys["vertex"], limiter)
    return [], True
