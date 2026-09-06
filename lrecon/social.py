from __future__ import annotations
import asyncio
import re

# --------------------------------------------------------------------------- #
# Brand-handle enumeration (Sherlock-style, adapted to org attack surface).
#
# Sherlock takes a username and checks ~400 sites for an account. We apply the
# same technique to the *organization's* handle rather than to individuals
# (Person is deliberately company-only, never personal accounts): check the
# brand handle across major platforms and flag the ones where it is
# *unregistered* — a squattable handle an attacker could grab to impersonate the
# org for phishing. Pure third-party OSINT: nothing here touches the target's own
# infrastructure.
#
# Classification is deliberately conservative, mirroring
# active.resolve_github_pages_claimability: a clear 404/410 (or a site's own
# "no such user" body) is `absent`; a 403/429/timeout/challenge is `unknown`,
# never a false "available". A wrong "squattable" is the costly error — it would
# send the operator to register a handle that is actually taken — so ambiguity
# always resolves to `unknown`, not `absent`.
# --------------------------------------------------------------------------- #

# A browser-ish UA cuts down on the reflexive 403s some platforms serve to
# non-browser clients (which we'd report honestly as `unknown` anyway).
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Curated, high-signal platforms with reliable presence detection. Kept small
# and accurate rather than exhaustive: a dozen platforms that 404 cleanly beat
# 400 that mostly cloak. `method` is "status" (200=present / 404=absent) unless a
# site returns 200 for missing handles, in which case "message" + `absent_if`
# (a substring only present on the not-found page) settles it. Bundled, never
# fetched at runtime.
SITES = {
    "GitHub":     {"url": "https://github.com/{}",                    "category": "code"},
    "GitLab":     {"url": "https://gitlab.com/{}",                    "category": "code"},
    "PyPI":       {"url": "https://pypi.org/user/{}/",                "category": "package"},
    "npm":        {"url": "https://www.npmjs.com/~{}",                "category": "package"},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}",              "category": "package"},
    "Keybase":    {"url": "https://keybase.io/{}",                    "category": "identity"},
    "Reddit":     {"url": "https://www.reddit.com/user/{}/about.json","category": "social"},
    "Medium":     {"url": "https://medium.com/@{}",                   "category": "social"},
    "YouTube":    {"url": "https://www.youtube.com/@{}",              "category": "social"},
    "Twitch":     {"url": "https://www.twitch.tv/{}",                 "category": "social"},
    "Pinterest":  {"url": "https://www.pinterest.com/{}/",            "category": "social"},
    "Instagram":  {"url": "https://www.instagram.com/{}/",            "category": "social"},
    "X/Twitter":  {"url": "https://x.com/{}",                         "category": "social"},
    "Facebook":   {"url": "https://www.facebook.com/{}",              "category": "social"},
    "TikTok":     {"url": "https://www.tiktok.com/@{}",               "category": "social"},
    "LinkedIn":   {"url": "https://www.linkedin.com/company/{}",      "category": "social"},
}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def brand_handles(domains, company_name: str | None = None) -> list:
    """Candidate org handles to check: each domain's label as-is (e.g.
    `acme-corp`) and slugified (`acmecorp`, valid where hyphens aren't), plus a
    slug of `--company-name` when given. Deduped, order preserved, empties
    dropped."""
    out = []
    for d in domains or []:
        label = str(d).split(".")[0].lower()
        out.append(label)
        out.append(_slug(label))
    if company_name:
        out.append(_slug(company_name))
    return list(dict.fromkeys(h for h in out if h))


async def check_handle(client, handle: str, sem, sites: dict | None = None) -> list:
    """`[{site, url, category, status}]` for `handle` across `sites` (default
    SITES). status is present / absent / unknown (see module docstring)."""
    sites = sites or SITES

    async def one(name, spec):
        url = spec["url"].format(handle)
        method = spec.get("method", "status")
        async with sem:
            try:
                r = await client.get(url, timeout=10, follow_redirects=True,
                                     headers={"User-Agent": _UA})
            except Exception:
                status = "unknown"
            else:
                code = r.status_code
                if code in (404, 410):
                    status = "absent"
                elif code == 200 and method == "message":
                    status = "absent" if spec.get("absent_if", "") in r.text else "present"
                elif code == 200:
                    status = "present"
                else:                                   # 403/429/5xx/redirects -> inconclusive
                    status = "unknown"
        return {"site": name, "url": url, "category": spec.get("category"), "status": status}

    return list(await asyncio.gather(*(one(n, s) for n, s in sites.items())))


async def enumerate_brand_handles(client, domains, company_name: str | None = None,
                                  concurrency: int = 10) -> dict:
    """`{handle: [site results]}` for each candidate org handle. Bounded fan-out
    so we stay polite to the third-party platforms."""
    handles = brand_handles(domains, company_name)
    if not handles:
        return {}
    sem = asyncio.Semaphore(concurrency)
    out = {}
    for h in handles:
        out[h] = await check_handle(client, h, sem)
    return out
