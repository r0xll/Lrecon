from __future__ import annotations
import asyncio, random, re, string
from .common import *
from .sources import get_resolver

# --------------------------------------------------------------------------- #
# Company-affiliated user enumeration (OSINT) — red-team phishing/password-
# spray candidate list. Deliberately company-domain data only: no personal
# accounts, no personal contact info. Every source here is either an official,
# documented API used with a user-supplied key (Hunter.io, RocketReach), or a
# passive search against data the target already published (GitHub code/
# commit history). Nothing here scrapes LinkedIn or any other platform
# directly — that would mean defeating anti-automation measures and violating
# those platforms' terms of service, a materially different (and riskier)
# category than the keyless/keyed APIs the rest of lrecon already uses.
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Hunter.io domain search — the primary source: known company emails + the
# detected naming convention, from an API purpose-built for this.
# --------------------------------------------------------------------------- #
def _parse_hunter_response(data: dict) -> tuple[str | None, list]:
    d = (data or {}).get("data", {}) or {}
    pattern = d.get("pattern")
    people = []
    for e in d.get("emails", []) or []:
        email = e.get("value")
        if not email:
            continue
        first = e.get("first_name") or ""
        last = e.get("last_name") or ""
        name = f"{first} {last}".strip() or None
        people.append(Person(email=email.lower(), name=name, position=e.get("position"),
                             confidence=e.get("confidence"), source={"hunter"}))
    return pattern, people


def _hunter_error_detail(payload) -> str:
    """Hunter's own explanation for a refusal, if it gave one.

    Hunter answers several non-obvious conditions (out of credits, plan doesn't
    include this endpoint, domain not searchable) with a body that explains
    itself while the status code alone does not — so a bare `HTTP 4xx` line
    throws away the only useful part of the response.
    """
    errs = (payload or {}).get("errors") if isinstance(payload, dict) else None
    details = [e.get("details") or e.get("id") for e in (errs or []) if isinstance(e, dict)]
    return " | ".join(d for d in details if d)


_HUNTER_CAP_RE = re.compile(r"limited to (\d+) email", re.I)


def hunter_plan_cap(detail: str) -> int | None:
    """The result cap Hunter's error names, if it named one.

    Asking for more than the plan allows is a hard 400, not a truncated result:
    "The search results are limited to 10 email addresses on your current plan."
    Every search failed because lrecon asked for 100. The number is read back
    out rather than hardcoded, since it is plan-specific and changes with the
    plan.
    """
    m = _HUNTER_CAP_RE.search(detail or "")
    return int(m.group(1)) if m else None


async def hunter_domain_search(client, domain: str, api_key: str,
                               limit: int = 100) -> tuple[str | None, list]:
    try:
        r = await client.get("https://api.hunter.io/v2/domain-search",
                            params={"domain": domain, "api_key": api_key, "limit": limit},
                            timeout=25)
        try:
            payload = r.json()
        except Exception:
            payload = None
        if r.status_code == 400:
            cap = hunter_plan_cap(_hunter_error_detail(payload))
            if cap and cap < limit:
                log(f"[i] hunter.io {domain}: plan caps results at {cap} — retrying at that "
                    f"limit (asked for {limit})")
                return await hunter_domain_search(client, domain, api_key, limit=cap)
        if r.status_code == 200:
            pattern, people = _parse_hunter_response(payload)
            if not people:
                # A 200 with zero emails is Hunter's answer for "nothing
                # indexed", but it is also what a credit-exhausted or
                # plan-restricted account gets. Say which, rather than letting
                # it read as "this domain has no exposed staff".
                d = (payload or {}).get("data") or {}
                log(f"[!] hunter.io {domain}: 200 but no emails returned "
                    f"(pattern={d.get('pattern') or 'none'}, "
                    f"total={(d.get('meta') or {}).get('results', '?')}"
                    + (f", {_hunter_error_detail(payload)}"
                       if _hunter_error_detail(payload) else "")
                    + ") — check remaining credits/plan before reading this as "
                      "'no exposure'")
            return pattern, people
        detail = _hunter_error_detail(payload)
        if r.status_code == 401:
            log(f"[!] hunter.io: invalid API key{' — ' + detail if detail else ''}")
        elif r.status_code == 429:
            log(f"[!] hunter.io: rate limited{' — ' + detail if detail else ''}")
        else:
            log(f"[!] hunter.io {domain}: HTTP {r.status_code}"
                + (f" — {detail}" if detail else ""))
    except Exception as e:
        log(f"[!] hunter.io {domain}: {e}")
    return None, []


# --------------------------------------------------------------------------- #
# GitHub code/commit history — company emails leaked in public repos. Reuses
# the caller's rate limiter (shared with github_dork() in intel.py — both hit
# the same ~10/min code-search quota).
# --------------------------------------------------------------------------- #
def _extract_emails_from_text_matches(items: list, domain: str) -> set:
    # Boundary check after the domain so "alice@example.com.au" or
    # "alice@example.company" (a different, longer domain) can't be truncated
    # into a false in-scope "alice@example.com" hit. Two lookaheads: reject an
    # immediately-following alnum/hyphen (unambiguous continuation, e.g.
    # ".company"), and reject a "." that's itself followed by an alnum (a
    # continuing label, e.g. ".com.au") — but allow a bare trailing "." as
    # ordinary sentence punctuation ("reach out to alice@example.com.").
    pattern = re.compile(
        r"[A-Za-z0-9._%+\-]+@" + re.escape(domain) + r"(?![A-Za-z0-9\-])(?!\.[A-Za-z0-9])",
        re.IGNORECASE)
    out = set()
    for item in items or []:
        for tm in item.get("text_matches", []) or []:
            for m in pattern.findall(tm.get("fragment", "") or ""):
                out.add(m.lower())
    return out


async def github_email_harvest(client, domain: str, token: str, limiter) -> set:
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github.v3.text-match+json",
               "User-Agent": "lrecon"}
    await limiter.wait()
    try:
        r = await client.get("https://api.github.com/search/code",
                            params={"q": f'"@{domain}"', "per_page": 30},
                            headers=headers, timeout=25)
        if r.status_code == 200:
            return _extract_emails_from_text_matches(r.json().get("items", []), domain)
        if r.status_code == 403:
            log("[!] github email harvest: rate limited")
    except Exception as e:
        log(f"[!] github email harvest: {e}")
    return set()


# --------------------------------------------------------------------------- #
# RocketReach — official API, best-effort. Deliberately does NOT call their
# credit-consuming "lookup/reveal" endpoint, so results here are name/title/
# LinkedIn-URL only (no personal contact fields, no email — see
# generate_candidate_emails for turning a name into a candidate company
# address instead).
#
# URL and request-body shape (base /api/v2/, POST {query, start, page_size})
# are confirmed against the official rocketreach_python client's source. The
# "current_employer_domain" filter field name is still best-effort — could
# not verify it against RocketReach's own API reference (docs pages return
# 403 to automated fetches) — but a wrong/unsupported filter field degrades
# to an empty result set rather than an error, and _parse_rocketreach_response
# degrades to an empty list rather than raising on any other unexpected
# response shape too.
# --------------------------------------------------------------------------- #
def _parse_rocketreach_response(data: dict) -> list:
    out = []
    for p in (data or {}).get("profiles", []) or []:
        name = p.get("name") or p.get("full_name")
        if not name:
            continue
        out.append({"name": name, "position": p.get("current_title") or p.get("title"),
                    "linkedin_url": p.get("linkedin_url")})
    return out


async def rocketreach_search(client, domain: str, company_name: str, api_key: str) -> list:
    try:
        r = await client.post("https://api.rocketreach.co/api/v2/search",
                             headers={"Api-Key": api_key, "User-Agent": "lrecon"},
                             json={"start": 1, "page_size": 25,
                                   "query": {"current_employer_domain": [domain]}},
                             timeout=30)
        if r.status_code == 200:
            return _parse_rocketreach_response(r.json())
        if r.status_code == 401:
            log("[!] rocketreach: invalid API key")
        elif r.status_code == 429:
            log("[!] rocketreach: rate limited")
        else:
            log(f"[!] rocketreach {domain}: HTTP {r.status_code} "
                "— API shape may differ from what lrecon expects")
    except Exception as e:
        log(f"[!] rocketreach {domain}: {e}")
    return []


# --------------------------------------------------------------------------- #
# Pattern-based candidate generation — for names discovered without a
# directly-observed email (currently: RocketReach hits), apply Hunter's
# detected naming convention to produce a candidate company address.
# Explicitly marked generated=True; never claimed as observed/confirmed.
# --------------------------------------------------------------------------- #
def _apply_pattern(pattern: str, first: str, last: str, domain: str) -> str | None:
    first, last = first.lower().strip(), last.lower().strip()
    if not first or not last:
        return None
    local = (pattern.replace("{first}", first).replace("{last}", last)
                    .replace("{f}", first[:1]).replace("{l}", last[:1]))
    if "{" in local:                      # unrecognized token -> bail rather than emit garbage
        return None
    return f"{local}@{domain}"


def generate_candidate_emails(names: list, domain: str, pattern: str | None) -> list:
    if not pattern:
        return []
    out = []
    for n in names:
        full = (n.get("name") or "").strip()
        if not full or " " not in full:
            continue
        first, *rest = full.split()
        last = rest[-1] if rest else ""
        email = _apply_pattern(pattern, first, last, domain)
        if email:
            out.append(Person(email=email, name=full, position=n.get("position"),
                              generated=True, source={"rocketreach+pattern"}))
    return out


# --------------------------------------------------------------------------- #
# SMTP RCPT-TO verification (opt-in, --verify-emails) — an ACTIVE technique
# that directly touches the target's live mail infrastructure; many orgs
# alert on it. Detects catch-all domains (a deliberately-nonexistent address
# accepted too) and labels every result "catch-all" instead of reporting
# false "valid" positives. Many providers (M365, Google Workspace, or
# anything blocking port 25 from cloud/datacenter source IPs) will make this
# come back "unknown" for the whole domain — expected, not a bug.
# --------------------------------------------------------------------------- #
def _rcpt_status(code: int) -> str:
    """
    Only 550 ("no such user") is a definitive rejection. Everything else
    outside 250/251 — 4xx temp-fail/greylisting, and other 5xx policy codes
    (mailbox full, relay restrictions, syntax quibbles) — is not proof the
    address doesn't exist, so it stays "unknown" rather than a false-negative
    "invalid" that would wrongly drop a real target from the candidate list.
    """
    if code in (250, 251):
        return "valid"
    if code == 550:
        return "invalid"
    return "unknown"


async def _smtp_read_response(reader) -> int:
    """Read a full (possibly multi-line '250-' continuation) SMTP response; return the status code."""
    code = 0
    while True:
        line = await reader.readline()
        if not line:
            break
        code = int(line[:3]) if line[:3].isdigit() else 0
        if len(line) < 4 or line[3:4] != b"-":     # no "-" continuation marker -> last line
            break
    return code


async def verify_emails(domain: str, emails: list, resolver_ns, mail_from: str | None = None,
                        timeout: float = 10.0) -> dict:
    out = {e: "unknown" for e in emails}
    if not _HAVE_DNS or not emails:
        return out
    res = get_resolver(resolver_ns)
    try:
        mx_records = sorted(await res.resolve(domain, "MX"), key=lambda r: r.preference)
        mx_host = str(mx_records[0].exchange).rstrip(".")
    except Exception as e:
        log(f"[!] email verify {domain}: no MX ({e})")
        return out

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(mx_host, 25), timeout=timeout)
    except Exception as e:
        log(f"[!] email verify {domain}: can't reach MX {mx_host} ({e})")
        return out

    async def cmd(line: str) -> int:
        writer.write((line + "\r\n").encode())
        await writer.drain()
        return await asyncio.wait_for(_smtp_read_response(reader), timeout=timeout)

    sender = mail_from or f"verify@{domain}"
    try:
        await asyncio.wait_for(_smtp_read_response(reader), timeout=timeout)   # banner
        await cmd("EHLO lrecon.local")
        code = await cmd(f"MAIL FROM:<{sender}>")
        if code >= 400:
            log(f"[!] email verify {domain}: MAIL FROM rejected ({code})")
            return out

        rand_local = "lrecon-verify-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        catchall_code = await cmd(f"RCPT TO:<{rand_local}@{domain}>")
        catchall_result = _rcpt_status(catchall_code)
        if catchall_result == "valid":
            log(f"[!] email verify {domain}: catch-all domain — results are inconclusive")
            for e in emails:
                out[e] = "catch-all"
        elif catchall_result == "unknown":
            # Ambiguous/temp-fail response even for a garbage address (e.g.
            # greylisting) — every real address probed on this connection
            # would hit the same ambiguity, so leave everything at the
            # "unknown" default rather than probing further.
            log(f"[!] email verify {domain}: ambiguous RCPT response (code {catchall_code}) "
                f"— treating as unknown rather than probing further")
        else:   # "invalid" — the server does reject nonexistent users, so real checks are meaningful
            for e in emails:
                code = await cmd(f"RCPT TO:<{e}>")
                out[e] = _rcpt_status(code)
        await cmd("QUIT")
    except Exception as e:
        log(f"[!] email verify {domain}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return out


# --------------------------------------------------------------------------- #
# Orchestration — one domain in, aggregated Person list out.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Keyless discovery: addresses the target published on its own website. Every
# other source here needs a key, so a scope with no Hunter/RocketReach/GitHub
# credentials produced an empty people list no matter how much the client had
# exposed — which reads as "no exposure" rather than "nothing was looked at".
#
# Only the target's own pages are fetched, and only addresses *at the in-scope
# domain* are kept: a partner's or a vendor's address appearing in a footer is
# not the client's exposure and is not ours to collect.
# --------------------------------------------------------------------------- #
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Where organisations put staff addresses. Kept short on purpose: this is one
# fetch each against a live host, and the long tail costs far more than it finds.
CONTACT_PATHS = ["/", "/contact", "/contact-us", "/about", "/about-us", "/team",
                 "/imprint", "/impressum", "/legal", "/privacy", "/support"]

# Role accounts are real exposure but not people, and they dominate a scrape.
# Tracked separately so a phishing target list isn't 80% info@.
ROLE_LOCALPARTS = {"info", "contact", "support", "sales", "admin", "webmaster",
                   "hello", "help", "noreply", "no-reply", "donotreply", "mail",
                   "office", "enquiries", "inquiries", "abuse", "postmaster",
                   "marketing", "press", "media", "legal", "privacy", "security",
                   "careers", "jobs", "hr", "billing", "accounts", "invoices"}


def extract_emails(text: str, domain: str) -> set:
    """In-scope addresses in a page, lowercased.

    Scoped to the domain rather than collecting everything the page mentions:
    a footer full of a vendor's contact addresses is that vendor's exposure, and
    hoovering it up would put out-of-scope people in an engagement deliverable.
    """
    if not text:
        return set()
    out = set()
    for m in EMAIL_RE.findall(text):
        e = m.lower().rstrip(".")
        local, _, host = e.partition("@")
        if not local or (host != domain and not host.endswith("." + domain)):
            continue
        # Assets like logo@2x.png and sprite@3x.svg match the address shape.
        if host.rsplit(".", 1)[-1] in ("png", "jpg", "jpeg", "gif", "svg", "webp"):
            continue
        out.add(e)
    return out


async def scrape_site_emails(probe_client, domain: str, hosts: list,
                             max_hosts: int = 5, max_pages: int = 6) -> set:
    """Addresses published on the target's own live web pages. Keyless.

    Active by touch tier — it fetches the target — so callers must gate it the
    same way the HTTP probe is gated. Bounded to a handful of hosts and pages so
    it stays a cheap add-on to a run rather than a crawl: this is contact-page
    discovery, not spidering.
    """
    live = [h for h in hosts
            if h.http_status and not h.wildcard
            and (h.subdomain == domain or h.subdomain.endswith("." + domain))]
    # An apex or www host is where a contact page actually lives; deeper hosts
    # are usually apps that just proxy the same footer.
    live.sort(key=lambda h: (h.subdomain.count("."), len(h.subdomain)))
    found = set()

    async def fetch(host, path):
        url = f"{host.scheme or 'https'}://{host.subdomain}{path}"
        try:
            r = await probe_client.get(url, timeout=10, follow_redirects=True)
            if r.status_code == 200:
                return extract_emails(r.text[:200000], domain)
        except Exception:
            pass
        return set()

    for host in live[:max_hosts]:
        results = await asyncio.gather(*(fetch(host, p) for p in CONTACT_PATHS[:max_pages]))
        for s in results:
            found |= s
    return found


def split_role_accounts(emails) -> tuple[list, list]:
    """(people, role_accounts). A shared mailbox is exposure worth reporting but
    is nobody to phish or spray, so the two are never merged into one count."""
    people, roles = [], []
    for e in sorted(emails):
        (roles if e.partition("@")[0] in ROLE_LOCALPARTS else people).append(e)
    return people, roles


async def enumerate_people(client, domain: str, keys: dict, gh_limiter, company_name: str | None = None) -> list:
    people_by_email = {}
    pattern = None

    if keys.get("hunter"):
        pattern, hunter_people = await hunter_domain_search(client, domain, keys["hunter"])
        for p in hunter_people:
            people_by_email[p.email] = p

    if keys.get("github"):
        harvested = await github_email_harvest(client, domain, keys["github"], gh_limiter)
        for email in harvested:
            if email in people_by_email:
                people_by_email[email].source.add("github")
            else:
                people_by_email[email] = Person(email=email, source={"github"})

    if keys.get("rocketreach"):
        rr_hits = await rocketreach_search(client, domain, company_name or domain.split(".")[0],
                                           keys["rocketreach"])
        for cand in generate_candidate_emails(rr_hits, domain, pattern):
            if cand.email in people_by_email:
                people_by_email[cand.email].source.add("rocketreach+pattern")
            else:
                people_by_email[cand.email] = cand

    return sorted(people_by_email.values(), key=lambda p: p.email)
