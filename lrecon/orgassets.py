from __future__ import annotations
import asyncio
from .secrets import scan_text
from .social import brand_handles

# --------------------------------------------------------------------------- #
# Org public-asset enumeration (BBOT github_org / postman / dockerhub style).
#
# Extends the existing GitHub dorking (`intel.github_dork`) and brand-handle
# presence (`social.py`): instead of checking whether the org's *handle* exists,
# enumerate the org's public code/collaboration assets and flag any secret-shaped
# string in the text we already fetch. Pure third-party OSINT — queries GitHub,
# Docker Hub and Postman public APIs only, never the target's own infrastructure.
#
# Conservative by design: list the assets and surface secret LEADS from the
# description / README text the listing already returns; no cloning, no deep
# crawl, no per-file tree walk. A `scan_text` hit is a lead the operator
# verifies (it may be a public/placeholder key), never a confirmation. Opt-in
# only (`--org-assets`), same third-party-disclosure posture as `--brand-handles`
# — never enabled by `--all`.
# --------------------------------------------------------------------------- #

_GH_API = "https://api.github.com"
_DOCKER_API = "https://hub.docker.com/v2"
_POSTMAN_SEARCH = "https://www.postman.com/_api/ws/proxy"
_UA = "lrecon"
_MAX_PAGES = 10          # hard page cap per source — complete without unbounded fan-out


def _gh_headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": _UA}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _next_link(headers) -> str | None:
    """The `rel="next"` URL from a GitHub-style Link header, or None. Tolerant of
    a response stub without headers (returns None)."""
    try:
        link = headers.get("link") or headers.get("Link")
    except Exception:
        return None
    if not link:
        return None
    for part in link.split(","):
        if 'rel="next"' in part:
            lb, rb = part.find("<"), part.find(">")
            if lb != -1 and rb != -1 and rb > lb:
                return part[lb + 1:rb]
    return None


async def github_org_repos(client, org: str, token: str | None, limiter=None,
                           readme_cap: int = 10, sem=None) -> list:
    """Public repos of GitHub org `org` as
    `[{name, full_name, url, description, archived, pushed_at, secrets:[...]}]`.

    A 404 (no such org) or any error yields `[]`. All pages are followed via the
    Link header (up to `_MAX_PAGES`) so a large org isn't silently truncated.
    `description` is always scanned for secret leads; the README is fetched and
    scanned for up to `readme_cap` repos (bounded, so a large org can't fan out
    without limit)."""
    repos = []
    url = f"{_GH_API}/orgs/{org}/repos"
    params = {"per_page": 100, "type": "public"}
    for _ in range(_MAX_PAGES):
        if limiter:
            await limiter.wait()
        try:
            r = await client.get(url, params=params, headers=_gh_headers(token), timeout=25)
        except Exception:
            break
        if r.status_code != 200:
            break
        try:
            items = r.json()
        except Exception:
            break
        if not isinstance(items, list):
            break
        for it in items:
            desc = it.get("description") or ""
            repos.append({
                "name": it.get("name"),
                "full_name": it.get("full_name"),
                "url": it.get("html_url"),
                "description": desc,
                "archived": bool(it.get("archived")),
                "pushed_at": it.get("pushed_at"),
                "secrets": list(scan_text(desc, it.get("html_url") or "")),
            })
        nxt = _next_link(getattr(r, "headers", None))
        if not nxt:
            break
        url, params = nxt, None          # the next link already carries the query

    if not repos:
        return []

    # README scan for the first `readme_cap` repos (bounded fan-out).
    sem = sem or asyncio.Semaphore(5)
    targets = [r for r in repos if r["full_name"]][:max(0, readme_cap)]

    async def one(repo):
        async with sem:
            if limiter:
                await limiter.wait()
            try:
                rr = await client.get(f"{_GH_API}/repos/{repo['full_name']}/readme",
                                      headers={**_gh_headers(token),
                                               "Accept": "application/vnd.github.raw+json"},
                                      timeout=20)
            except Exception:
                return
            if rr.status_code != 200:
                return
            for f in scan_text(rr.text[:200000], f"{repo['url']}#readme"):
                if f not in repo["secrets"]:
                    repo["secrets"].append(f)

    if targets:
        await asyncio.gather(*(one(r) for r in targets))
    return repos


async def docker_hub_images(client, namespace: str) -> list:
    """Public Docker Hub images under `namespace` as
    `[{name, namespace, url, description, pull_count, last_updated, secrets:[...]}]`.
    Keyless. A 404 or error yields `[]`; the image description is scanned. All
    pages are followed via the API's `next` URL (up to `_MAX_PAGES`) so a large
    namespace isn't silently truncated."""
    out = []
    url = f"{_DOCKER_API}/repositories/{namespace}/"
    params = {"page_size": 100}
    for _ in range(_MAX_PAGES):
        try:
            r = await client.get(url, params=params, headers={"User-Agent": _UA}, timeout=20)
        except Exception:
            break
        if r.status_code != 200:
            break
        try:
            data = r.json()
        except Exception:
            break
        for it in (data.get("results") or []):
            if it.get("is_private"):
                continue
            name = it.get("name")
            desc = it.get("description") or ""
            u = f"https://hub.docker.com/r/{namespace}/{name}"
            out.append({
                "name": name,
                "namespace": namespace,
                "url": u,
                "description": desc,
                "pull_count": it.get("pull_count"),
                "last_updated": it.get("last_updated"),
                "secrets": list(scan_text(desc, u)),
            })
        nxt = data.get("next")           # Docker Hub returns a full next-page URL
        if not nxt:
            break
        url, params = nxt, None
    return out


async def postman_search(client, query: str) -> list:
    """Best-effort public Postman workspace/collection search for `query` as
    `[{name, url, workspace, secrets:[...]}]`.

    Postman's public search is an undocumented internal endpoint, so this is
    deliberately defensive: any non-200, shape mismatch or parse error yields
    `[]` rather than raising. Never touches the target — queries postman.com."""
    body = {
        "service": "search",
        "method": "POST",
        "path": "/search-all",
        "body": {"queryText": query, "domain": "public",
                 "collectionId": "", "requestOrigin": "srp",
                 "mergeEntities": True, "nonNestedRequests": True,
                 "size": 25, "from": 0},
    }
    try:
        r = await client.post(_POSTMAN_SEARCH, json=body,
                              headers={"User-Agent": _UA,
                                       "Content-Type": "application/json"},
                              timeout=20)
    except Exception:
        return []
    if r.status_code != 200:
        return []
    try:
        data = r.json().get("data", [])
    except Exception:
        return []

    out = []
    for it in data or []:
        doc = it.get("document", it) if isinstance(it, dict) else {}
        name = doc.get("name") or doc.get("workspaceName")
        if not name:
            continue
        slug = doc.get("publisherHandle") or doc.get("publisherName") or ""
        pid = doc.get("id") or doc.get("publicId") or ""
        url = f"https://www.postman.com/{slug}/{pid}".rstrip("/")
        blob = " ".join(str(doc.get(k) or "") for k in ("name", "description", "summary"))
        out.append({
            "name": name,
            "url": url,
            "workspace": doc.get("workspaceName") or doc.get("workspaceSlug"),
            "secrets": list(scan_text(blob, url)),
        })
    return out


def _flatten_secret_hits(github_repos, docker_images, postman) -> list:
    """One flat list of secret leads across every asset, for entry points:
    `[{source, asset, url, kind, masked}]`."""
    hits = []
    for r in github_repos:
        for s in r.get("secrets", []):
            hits.append({"source": "github", "asset": r.get("full_name"),
                         "url": r.get("url"), "kind": s["kind"], "masked": s["masked"]})
    for img in docker_images:
        for s in img.get("secrets", []):
            hits.append({"source": "dockerhub", "asset": f"{img.get('namespace')}/{img.get('name')}",
                         "url": img.get("url"), "kind": s["kind"], "masked": s["masked"]})
    for p in postman:
        for s in p.get("secrets", []):
            hits.append({"source": "postman", "asset": p.get("name"),
                         "url": p.get("url"), "kind": s["kind"], "masked": s["masked"]})
    return hits


async def enumerate_org_assets(client, domains, company_name: str | None = None,
                               github_token: str | None = None, limiter=None,
                               readme_cap: int = 10) -> dict:
    """Enumerate the org's public GitHub / Docker Hub / Postman assets and flag
    secret leads in their text. Returns
    `{org_candidates, github_repos, docker_images, postman, secret_hits}`.

    `org_candidates` are the handle slugs tried (from `social.brand_handles`:
    each domain label + slug + a `--company-name` slug). GitHub and Docker Hub
    are queried per candidate; Postman is searched by company name and each
    domain. All lookups degrade to empty on error — a blocked platform never
    fails the run."""
    candidates = brand_handles(domains, company_name)
    result = {"org_candidates": candidates, "github_repos": [],
              "docker_images": [], "postman": [], "secret_hits": []}
    if not candidates:
        return result

    gh_sem = asyncio.Semaphore(5)
    seen_repos, seen_imgs = set(), set()
    for org in candidates:
        for repo in await github_org_repos(client, org, github_token, limiter,
                                            readme_cap=readme_cap, sem=gh_sem):
            if repo["full_name"] and repo["full_name"] not in seen_repos:
                seen_repos.add(repo["full_name"])
                result["github_repos"].append(repo)
        for img in await docker_hub_images(client, org):
            key = f"{img['namespace']}/{img['name']}"
            if key not in seen_imgs:
                seen_imgs.add(key)
                result["docker_images"].append(img)

    # Postman: search by company name and each domain (deduped by url).
    queries = []
    if company_name:
        queries.append(company_name)
    queries += [str(d) for d in (domains or [])]
    seen_pm = set()
    for q in dict.fromkeys(q for q in queries if q):
        for p in await postman_search(client, q):
            if p["url"] not in seen_pm:
                seen_pm.add(p["url"])
                result["postman"].append(p)

    result["secret_hits"] = _flatten_secret_hits(
        result["github_repos"], result["docker_images"], result["postman"])
    return result
