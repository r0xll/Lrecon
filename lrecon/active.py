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
            body = r.text[:30000]
            lo = body.lower()
            if "<title" in lo:
                s = lo.find(">", lo.find("<title")) + 1
                e = lo.find("</title", s)
                if s > 0 and e > s:
                    host.http_title = body[s:e].strip()[:120]
            _check_takeover(host, lo)
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
            _check_takeover(host, r.text[:30000].lower())
            return
        except Exception:
            continue


def mark_dangling_cname(host: Host, status: str) -> None:
    """Record a takeover lead from the CNAME target's DNS status.

    Only "nxdomain" is a finding — the target's name does not exist, so the
    hostname points at nothing and whoever can claim that name at the provider
    serves content here. "resolves" and "unknown" (timeout/SERVFAIL) are not
    reported: an inconclusive lookup must not become a client-facing finding.

    This is the one takeover signal needing neither an HTTP response nor a
    per-provider signature, and it covers exactly what _check_takeover() cannot
    see: a host with no A record never reaches the HTTP probe, which is the
    normal shape of a dangling CNAME. A known provider is named when the target
    matches one, but detection does not depend on it.

    An existing signature-based finding is left in place — it already carries
    corroborating body evidence.
    """
    if status != "nxdomain" or host.takeover:
        return
    provider = next((sig for sig in TAKEOVER_SIGS if host.cname and sig in host.cname), None)
    host.takeover = (f"Dangling CNAME -> {host.cname}"
                     + (f" ({provider})" if provider else "")
                     + "; target name does not exist (NXDOMAIN) — claimable if the "
                       "provider allows re-registration")
    host.takeover_confidence = "confirmed"


def _check_takeover(host: Host, body_lower: str) -> None:
    if not host.cname:
        return
    for cname_sig, body_sigs in TAKEOVER_SIGS.items():
        if cname_sig in host.cname:
            for bsig in body_sigs:
                if bsig in body_lower:
                    host.takeover = (f"Dangling CNAME -> {host.cname} "
                                     f"({cname_sig}); unclaimed-service signature matched")
                    host.takeover_confidence = "likely"
                    return
            host.takeover = (f"CNAME -> {host.cname} ({cname_sig}); verify service ownership")
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


