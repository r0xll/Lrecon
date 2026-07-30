from __future__ import annotations
import asyncio, ipaddress, random, shutil, string
from .common import *
from . import backends
try:
    import dns.asyncresolver
except Exception:
    pass

# --------------------------------------------------------------------------- #
# Phase 1 — passive enumeration sources (keyless unless noted)
# --------------------------------------------------------------------------- #
async def enum_crtsh_best(client, domain: str, use_psql: bool = True) -> set:
    """
    Prefer a direct query against crt.sh's public Postgres replica (psql, if
    on PATH) over its HTTP/JSON frontend — the direct-DB path bypasses that
    frontend's well-documented flakiness (429s/5xx/outright outages) entirely
    rather than just retrying it. Falls back to enum_crtsh() (HTTP, already
    hardened with its own retry/backoff) when psql isn't available, or when
    it ran but produced nothing — cheap insurance against a silent
    connection failure looking identical to a genuinely empty result.

    The psql tier is bounded by short timeouts (see backends.crtsh_psql):
    where raw TCP :5432 is firewalled the connect hangs rather than refusing,
    so an unbounded first tier would stall every domain before the HTTP tier
    ever runs — which presents as "crt.sh doesn't work" even though the HTTP
    path is fine.
    """
    if use_psql:
        rows = await backends.crtsh_psql(domain)
        if rows:
            # Same label-boundary scoping as the HTTP tier — see
            # _crtsh_name_in_scope (a bare endswith would accept
            # testexample.com for example.com).
            out = {n.strip().lstrip("*.").lower().rstrip(".") for n in rows}
            out = {n for n in out if _crtsh_name_in_scope(n, domain)}
            if out:
                return out
        log(f"[i] crt.sh {domain}: direct-DB tier unavailable/empty — using HTTP frontend "
            f"(--no-pd skips the psql tier entirely)")
    return await enum_crtsh(client, domain)


# crt.sh returns 502/504 mostly when its own query planner times out on a big
# result set, so these are worth retrying — and worth shrinking the query for.
_CRTSH_RETRY_STATUS = (429, 500, 502, 503, 504)


def _crtsh_name_in_scope(name: str, domain: str) -> bool:
    """
    True only for the apex itself or a real subdomain of it.

    A bare `endswith(domain)` test is wrong at the label boundary: it accepts
    `testexample.com` for `example.com` (confirmed live — crt.sh's
    `%.example.com` pattern does return names like `m.testexample.com`). Adding
    an out-of-scope third party's host to an engagement's scope is an ROE
    problem, not a cosmetic one, so the boundary is checked explicitly.

    Email addresses are also rejected: certificate subjects can carry an
    rfc822Name (e.g. `subjectname@example.com`), which is not a host to scan.
    The psql tier already excludes these server-side (`NOT ILIKE '%@%'`); this
    keeps the HTTP tier consistent with it.
    """
    if not name or " " in name or "@" in name:
        return False
    return name == domain or name.endswith("." + domain)


def _parse_crtsh_rows(rows, domain: str) -> set:
    """Names out of crt.sh's JSON rows, scoped to `domain`. Each row carries a
    newline-separated `name_value` (SAN list) plus a `common_name`."""
    out = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = f"{row.get('name_value', '')}\n{row.get('common_name') or ''}"
        for n in names.splitlines():
            n = n.strip().lstrip("*.").lower().rstrip(".")
            if _crtsh_name_in_scope(n, domain):
                out.add(n)
    return out


async def enum_crtsh(client, domain: str) -> set:
    """
    crt.sh's web frontend is notoriously flaky under load (slow queries, 429s,
    5xx, or a truncated/non-JSON body on a 200) — retry with exponential
    backoff + jitter rather than giving up after one retry. Non-200/bad-JSON
    responses are retried too, not just network exceptions.

    Two query forms are alternated across attempts. Both are documented and
    cover the same identity pattern, but they take different paths through
    crt.sh's backend, so one frequently succeeds while the other 502s
    (measured: `identity=` returned 77 names while `q=` was 502-ing, and vice
    versa minutes later):

      1. ?q=%.{domain}          — wildcard match on the identity
      2. ?identity=%.{domain}   — explicit identity lookup

    Deliberately does NOT send `exclude=expired`. It looks attractive (smaller
    result set = fewer planner timeouts) but measured against example.com it
    dropped 77 names to 20 — and expired certs are exactly where forgotten
    dev/staging hostnames live, which is the point of CT enumeration. It also
    didn't actually stop the 502s.

    On total failure the per-attempt statuses are logged, so a bad run is
    diagnosable instead of looking like a silent empty result.
    """
    out = set()
    errors = []
    attempts = 5
    for attempt in range(attempts):
        # Alternate the two query forms so a planner timeout on one doesn't
        # burn every attempt.
        if attempt % 2 == 0:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
        else:
            url = f"https://crt.sh/?identity=%25.{domain}&output=json"
        try:
            r = await client.get(url, headers={"Accept": "application/json"}, timeout=45)
            if r.status_code == 200:
                try:
                    rows = r.json()
                except Exception as e:
                    # A 200 carrying a truncated/HTML body is a crt.sh failure
                    # mode, not an empty result — retry rather than accept it.
                    errors.append(f"200 but bad JSON ({e})")
                    rows = None
                if isinstance(rows, list):
                    if rows:
                        return _parse_crtsh_rows(rows, domain)
                    # An empty list is a legitimate "no certs" answer, but it's
                    # also what a truncated response looks like. Accept it only
                    # on the final attempt.
                    errors.append("200 with empty result")
                elif rows is not None:
                    errors.append(f"200 but unexpected JSON type ({type(rows).__name__})")
            else:
                errors.append(f"HTTP {r.status_code}")
                if r.status_code not in _CRTSH_RETRY_STATUS:
                    break      # 4xx other than 429 won't fix itself
        except Exception as e:
            errors.append(f"{type(e).__name__}: {e}")
        if attempt < attempts - 1:
            await asyncio.sleep(min(2 ** (attempt + 1), 20) + random.uniform(0, 1))
    if errors:
        log(f"[!] crt.sh {domain}: no data after {len(errors)} attempt(s) "
            f"[{'; '.join(errors[:5])}] — other CT sources (certspotter/OTX) still cover this")
    return out


async def enum_certspotter(client, domain: str) -> set:
    """CT via Cert Spotter — independent of crt.sh (survives crt.sh outages)."""
    out = set()
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    try:
        r = await client.get(url, timeout=30)
        if r.status_code == 200:
            for cert in r.json():
                for n in cert.get("dns_names", []):
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain):
                        out.add(n)
    except Exception as e:
        log(f"[!] certspotter {domain}: {e}")
    return out


async def enum_otx(client, domain: str) -> set:
    """AlienVault OTX passive DNS — keyless."""
    out = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = await client.get(url, timeout=30)
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                h = rec.get("hostname", "").strip().lower()
                if h.endswith(domain):
                    out.add(h)
    except Exception as e:
        log(f"[!] otx {domain}: {e}")
    return out


async def enum_anubis(client, domain: str) -> set:
    """jldc.me Anubis subdomain DB — keyless."""
    out = set()
    try:
        r = await client.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=30)
        if r.status_code == 200:
            for n in r.json():
                n = n.strip().lower()
                if n.endswith(domain):
                    out.add(n)
    except Exception as e:
        log(f"[!] anubis {domain}: {e}")
    return out


async def enum_wayback(client, domain: str) -> set:
    out = set()
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=10000")
    try:
        r = await client.get(url, timeout=45)
        if r.status_code == 200:
            for row in r.json()[1:]:
                host = row[0].split("//")[-1].split("/")[0].split(":")[0].lower()
                if host.endswith(domain):
                    out.add(host)
    except Exception as e:
        log(f"[!] wayback {domain}: {e}")
    return out


async def enum_shodan_dns(client, domain: str, key: str) -> set:
    out = set()
    try:
        r = await client.get(f"https://api.shodan.io/dns/domain/{domain}?key={key}", timeout=30)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                out.add(f"{sub}.{domain}".lower())
        elif r.status_code == 401:
            log("[!] Shodan: invalid API key")
    except Exception as e:
        log(f"[!] shodan dns {domain}: {e}")
    return out


async def enum_subfinder(domain: str) -> set:
    if not shutil.which("subfinder"):
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-silent", "-d", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        return {l.strip().lower() for l in out.decode().splitlines() if l.strip()}
    except Exception as e:
        log(f"[!] subfinder {domain}: {e}")
        return set()


async def passive_enum(client, domains, keys, no_pd: bool = False) -> tuple[dict, dict]:
    """
    Returns (host_sources, per_source_counts):
      host_sources: {hostname -> set(source_names)}
      per_source_counts: {source_name -> count of in-scope hosts it found}
    Every source is fanned out across every domain concurrently.
    """
    jobs = []                                       # (source_name, coroutine)
    for d in domains:
        jobs += [
            ("crtsh",       enum_crtsh_best(client, d, use_psql=not no_pd)),
            ("certspotter", enum_certspotter(client, d)),
            ("otx",         enum_otx(client, d)),
            ("anubis",      enum_anubis(client, d)),
            ("wayback",     enum_wayback(client, d)),
            ("subfinder",   enum_subfinder(d)),
        ]
        if keys.get("shodan"):
            jobs.append(("shodan_dns", enum_shodan_dns(client, d, keys["shodan"])))

    results = await asyncio.gather(*(c for _, c in jobs), return_exceptions=True)

    host_sources: dict = defaultdict(set)
    per_source: dict = defaultdict(int)
    for (src, _), res in zip(jobs, results):
        if isinstance(res, set):
            in_scope = {n for n in res if any(n.endswith(d) for d in domains)}
            per_source[src] += len(in_scope)
            for n in in_scope:
                host_sources[n].add(src)
    for d in domains:                               # seed apexes
        host_sources[d].add("seed")
    return host_sources, per_source



# --------------------------------------------------------------------------- #
# Phase 2 — resolution
# --------------------------------------------------------------------------- #
_RESOLVER = None


def get_resolver(nameservers):
    global _RESOLVER
    if _RESOLVER is None:
        r = dns.asyncresolver.Resolver(configure=True)
        if nameservers:
            r.nameservers = nameservers
        r.timeout, r.lifetime = 2.0, 4.0
        _RESOLVER = r
    return _RESOLVER


async def resolve_full(subdomain: str, nameservers) -> tuple:
    if not _HAVE_DNS:
        return [], None
    res = get_resolver(nameservers)

    async def q(rtype):
        try:
            return rtype, await res.resolve(subdomain, rtype)
        except Exception:
            return rtype, None

    ips, cname = [], None
    for rtype, ans in await asyncio.gather(q("A"), q("AAAA"), q("CNAME")):
        if ans is None:
            continue
        if rtype == "CNAME":
            cname = str(ans[0].target).rstrip(".").lower()
        else:
            ips.extend(str(r) for r in ans)
    return ips, cname


async def cname_target_status(cname: str, nameservers) -> str:
    """Whether a CNAME's target actually exists — the dangling-CNAME test.

    Returns "nxdomain" (the target's name does not exist: the highest-confidence
    subdomain-takeover signal there is), "resolves" (the target exists), or
    "unknown" (timeout/SERVFAIL — inconclusive, and must never be reported as a
    finding).

    This is what catches the takeovers TAKEOVER_SIGS cannot. The classic
    dangling CNAME has no A/AAAA record at all, so the host is filtered out
    before the HTTP probe and no body signature can ever match; NXDOMAIN on the
    target needs no HTTP request and no per-provider signature, so it works for
    providers nobody has written a signature for yet.

    A query for A/AAAA follows the CNAME chain, so a chain ending at a
    non-existent name reports NXDOMAIN here even when intermediate links exist.
    """
    if not _HAVE_DNS or not cname:
        return "unknown"
    res = get_resolver(nameservers)
    nxdomain = False
    for rtype in ("A", "AAAA"):
        try:
            if await res.resolve(cname, rtype):
                return "resolves"
        except Exception as e:
            kind = type(e).__name__
            if kind == "NXDOMAIN":
                nxdomain = True
            elif kind == "NoAnswer":
                return "resolves"     # the name exists, just not with this type
            # anything else (timeout, SERVFAIL, ...) stays inconclusive
    return "nxdomain" if nxdomain else "unknown"


async def detect_wildcard(domain: str, nameservers) -> set:
    if not _HAVE_DNS:
        return set()
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    ips, _ = await resolve_full(f"{rand}.{domain}", nameservers)
    if ips:
        log(f"[!] wildcard DNS on {domain} -> {', '.join(ips)} (filtering phantoms)")
    return set(ips)



# --------------------------------------------------------------------------- #
# ASN / netblock expansion (RIPEstat, keyless) + reverse-DNS sweep
# --------------------------------------------------------------------------- #
async def ripestat_prefixes(client, asn: str) -> list:
    """Announced prefixes for an ASN via RIPEstat (keyless)."""
    asn_num = asn.replace("AS", "").strip()
    out = []
    try:
        r = await client.get("https://stat.ripe.net/data/announced-prefixes/data.json",
                            params={"resource": f"AS{asn_num}"}, timeout=25)
        if r.status_code == 200:
            for p in r.json().get("data", {}).get("prefixes", []):
                out.append(p["prefix"])
    except Exception as e:
        log(f"[!] ripestat AS{asn_num}: {e}")
    return out


async def reverse_dns_sweep(prefixes, resolver_ns, cap=4096) -> dict:
    """PTR-sweep IPv4 prefixes (bounded). Returns {ip: hostname}."""
    if not _HAVE_DNS:
        return {}
    res = get_resolver(resolver_ns)
    targets = []
    for pfx in prefixes:
        try:
            net = ipaddress.ip_network(pfx, strict=False)
        except Exception:
            continue
        if net.version != 4 or net.num_addresses > 65536:   # skip v6 + huge nets
            continue
        for ip in net.hosts():
            targets.append(str(ip))
            if len(targets) >= cap:
                break
        if len(targets) >= cap:
            break
    sem = asyncio.Semaphore(100)
    found = {}

    async def ptr(ip):
        async with sem:
            try:
                ans = await res.resolve_address(ip)
                if ans:
                    found[ip] = str(ans[0].target).rstrip(".").lower()
            except Exception:
                pass
    await asyncio.gather(*(ptr(ip) for ip in targets))
    return found


