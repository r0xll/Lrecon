from __future__ import annotations
import asyncio
import httpx
from .common import *

# --------------------------------------------------------------------------- #
# Phase 4 — active
# --------------------------------------------------------------------------- #
async def http_probe(client, host: Host) -> None:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host.subdomain}",
                                timeout=10, follow_redirects=True)
            host.http_status = r.status_code
            host.scheme = scheme
            host.server = r.headers.get("server")
            host.powered_by = r.headers.get("x-powered-by")
            host.final_url = str(r.url)
            # Feed the same field the ProjectDiscovery httpx backend fills, so
            # confirm_tech_stack() has something to compare CPEs against. It
            # previously only ever got data on runs where PD httpx was on PATH,
            # which meant CVE tech-confirmation silently did nothing for anyone
            # on the pure-Python path — always None, never True or False.
            host.tech = [t for t in (host.server, host.powered_by) if t]
            body = r.text[:30000]
            lo = body.lower()
            if "<title" in lo:
                s = lo.find(">", lo.find("<title")) + 1
                e = lo.find("</title", s)
                if s > 0 and e > s:
                    host.http_title = body[s:e].strip()[:120]
            _check_takeover(host, lo, r.status_code)
            return
        except Exception:
            continue


async def takeover_check_host(client, host: Host) -> None:
    """Takeover-only body fetch, used when a backend already did the HTTP probe."""
    if not host.cname or not any(sig in host.cname for sig in TAKEOVER_SIGS):
        return
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host.subdomain}",
                                timeout=8, follow_redirects=True)
            _check_takeover(host, r.text[:30000].lower(), r.status_code)
            return
        except Exception:
            continue


def mark_dangling_cname(host: Host, status: str, closest_zone: str | None = None) -> None:
    """Record a takeover lead from the CNAME target's DNS status.

    Only "nxdomain" is a finding. "resolves" and "unknown" (timeout/SERVFAIL) are
    not reported: an inconclusive lookup must not become a client-facing finding.

    Confidence turns on *claimability*, not on brokenness. NXDOMAIN proves the
    target does not exist; it does not prove an attacker could create it. A
    broken CNAME to a typo under a partner's domain is NXDOMAIN too, yet nobody
    outside that partner can register the name — calling that a confirmed
    takeover would be a critical-severity false positive.

    So "confirmed" is reserved for SELF_SERVE providers, where re-registering the
    exact name is the service on offer. ACCOUNT_BOUND targets stay "possible" —
    the hostname is provider-assigned, and only the provider's domain
    verification decides whether the domain can be attached elsewhere.
    NOT_CLAIMABLE targets are not takeover findings at all; they are recorded as
    stale DNS, because the name can never be issued again.

    An unrecognised provider is "possible", carrying the closest still-existing
    zone as the evidence an operator needs to judge: a zone of `com` means the
    whole domain is unregistered and can simply be bought, while
    `partner-company.com` means only a label is missing inside someone else's
    live zone.

    This still covers what _check_takeover() structurally cannot see: a host with
    no A record never reaches the HTTP probe, which is the normal shape of a
    dangling CNAME. An existing signature-based finding is left in place — it
    already carries corroborating body evidence.
    """
    if status != "nxdomain" or host.takeover:
        return
    entry = next(((sig, claim) for sig, (claim, _b) in TAKEOVER_SIGS.items()
                  if host.cname and sig in host.cname), None)
    if entry:
        provider, claim = entry
        if claim == NOT_CLAIMABLE:
            # Dead, but nobody can have it. Reporting this as a takeover lead
            # sends an operator chasing a name the provider will never issue
            # again; the finding is the stale record itself.
            host.stale_dns = (f"CNAME -> {host.cname} ({provider}); target no longer exists "
                              f"(NXDOMAIN). The name is provider-assigned and cannot be "
                              f"re-created, so this is not a takeover — remove the record")
            return
        if claim == ACCOUNT_BOUND:
            host.takeover = (f"Dangling CNAME -> {host.cname} ({provider}); target name does "
                             f"not exist (NXDOMAIN). The hostname itself is provider-assigned, "
                             f"but the domain pointing at it may be attachable to another "
                             f"account — the provider's domain verification decides it")
            host.takeover_confidence = "possible"
            return
        host.takeover = (f"Dangling CNAME -> {host.cname} ({provider}); target name does "
                         f"not exist (NXDOMAIN) and the provider allows re-registration "
                         f"— claimable")
        host.takeover_confidence = "confirmed"
        return
    host.takeover = (f"Dangling CNAME -> {host.cname}; target name does not exist "
                     f"(NXDOMAIN)"
                     + (f", closest existing zone is {closest_zone}" if closest_zone else "")
                     + ". Broken, but claimability is unverified — confirm whether the "
                       "target is registrable before treating this as a takeover")
    host.takeover_confidence = "possible"


GITHUB_PAGES_SUFFIX = ".github.io"


def github_pages_account(cname: str | None) -> str | None:
    """The GitHub account a Pages CNAME target names, or None if it isn't one.

    Only `<account>.github.io` is a Pages host. Deeper names like
    `a.b.github.io` are not served by Pages, so there is no account to check and
    guessing one would produce a claim about the wrong thing.
    """
    if not cname:
        return None
    norm = cname.lower().rstrip(".")
    if not norm.endswith(GITHUB_PAGES_SUFFIX):
        return None
    label = norm[: -len(GITHUB_PAGES_SUFFIX)]
    return label if label and "." not in label else None


async def resolve_github_pages_claimability(client, host: Host, token=None) -> None:
    """Decide whether a GitHub Pages takeover lead is actually claimable.

    A Pages site is named after the account that owns it, and claiming a domain
    that points at one requires owning that account — so the username in the
    CNAME target settles it. The body signature cannot: GitHub serves the same
    "Site not found" page whether the account is unregistered or simply has no
    site published, so a working org's stale DNS looks exactly like a free name.

      * account 404 — the username is unregistered. Anyone can take it and serve
        content at that hostname: a real, confirmed takeover.
      * account 200 — the username is taken, so no third party can claim it. The
        record is stale rather than dangerous, and drops out of the takeover list.

    Any other outcome (rate limit, network failure) leaves the existing finding
    exactly as it was. A lookup that didn't happen is not evidence in either
    direction, and quietly downgrading on a 403 would hide real takeovers.

    Note this reasoning is specific to CNAMEs. A domain pointed at the Pages
    A records names no account at all; lrecon's takeover path is CNAME-keyed and
    never sees that shape.
    """
    account = github_pages_account(host.cname)
    if not account or not host.takeover:
        return
    headers = {"User-Agent": "lrecon", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = await client.get(f"https://api.github.com/users/{account}",
                             headers=headers, timeout=15)
    except Exception:
        return
    if r.status_code == 404:
        host.takeover = (f"Dangling CNAME -> {host.cname} (github.io); GitHub account "
                         f"'{account}' does not exist — registering the username claims "
                         f"this hostname")
        host.takeover_confidence = "confirmed"
    elif r.status_code == 200:
        host.stale_dns = (f"CNAME -> {host.cname} (github.io); no Pages site is published, "
                          f"but the GitHub account '{account}' exists, so no one else can "
                          f"claim it — not a takeover, remove the record")
        host.takeover = None
        host.takeover_confidence = None


def _check_takeover(host: Host, body_lower: str, status: int | None = None) -> None:
    """Match the served body against the provider's unclaimed-service signature.

    A signature match is the finding. A CNAME *into* a takeover-prone provider is
    not one: every healthy site on GitHub Pages, Fastly, Heroku or S3 has exactly
    that, and reporting it produced a takeover row for every working host on the
    target — noise that buries the real leads.

    An error status with no recognised signature is kept as a weak lead, since a
    provider that has reworded its unclaimed page still errors. A 2xx serving
    ordinary content is a working site and produces nothing.
    """
    if not host.cname:
        return
    for cname_sig, (_claim, body_sigs) in TAKEOVER_SIGS.items():
        if cname_sig not in host.cname:
            continue
        if any(bsig in body_lower for bsig in body_sigs):
            host.takeover = (f"Dangling CNAME -> {host.cname} "
                             f"({cname_sig}); unclaimed-service signature matched")
            host.takeover_confidence = "likely"
        elif status in TAKEOVER_ERROR_STATUSES:
            host.takeover = (f"CNAME -> {host.cname} ({cname_sig}); provider returned "
                             f"HTTP {status} with no known unclaimed-service signature "
                             f"— verify service ownership")
            host.takeover_confidence = "possible"
        return


async def tcp_scan(host: Host, ports, sem) -> None:
    async def probe(ip, port):
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None
    if not host.ips:
        return
    ip = host.ips[0]
    results = await asyncio.gather(*(probe(ip, p) for p in ports))
    open_ports = [p for p in results if p]
    if open_ports:
        host.ports = sorted(set(host.ports) | set(open_ports))


