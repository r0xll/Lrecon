from __future__ import annotations
import asyncio, ipaddress, ssl
from datetime import datetime, timezone
from .common import *

# --------------------------------------------------------------------------- #
# Live TLS certificate inspection.
#
# Everything else in lrecon learns about certificates second-hand — CT logs
# (crt.sh / certspotter) and Shodan's `ssl.cert.subject.CN` search. Reading the
# cert a host actually serves adds three things those cannot:
#
#   * SAN mining — names on the live cert that never reached a CT log, or that
#     sit on non-web TLS ports (465/993/8443/…) nobody submits to CT.
#   * Cloudflare origin confirmation — an origin rarely answers a spoofed Host
#     header convincingly, but it usually still serves a cert naming the target.
#     That is far stronger evidence than "the Server header didn't say
#     cloudflare".
#   * Hygiene facts an operator needs anyway: self-signed, expired, issuer.
#
# Certificates are read WITHOUT verification (check_hostname=False,
# CERT_NONE) for the same reason `probe_client` exists in core.py: engagement
# targets routinely serve self-signed, expired or mismatched certs, and those
# are exactly the ones worth reporting. Reading a cert is not trusting it — no
# request is sent beyond the handshake.
#
# `cryptography` is an OPTIONAL dependency (extra: `tls`), following the same
# convention as dnspython/rich/the ProjectDiscovery binaries: absent, the
# feature logs once and skips rather than breaking a run.
# --------------------------------------------------------------------------- #
try:
    from cryptography import x509
    HAVE_CRYPTO = True
except (KeyboardInterrupt, SystemExit):            # pragma: no cover
    raise
except BaseException:                              # pragma: no cover - env dependent
    # Deliberately broader than `except Exception`. cryptography's Rust
    # extension raises pyo3's PanicException — which derives straight from
    # BaseException — when its native bits are half-installed (e.g. a distro
    # package whose _cffi_backend is missing). That is a realistic broken
    # install, and it must degrade to "feature unavailable", not take the whole
    # scan down on import.
    HAVE_CRYPTO = False

# Ports worth reading a cert from when a host has them open. Web ports first,
# then the mail/admin TLS services whose certs are commonly forgotten and
# frequently carry internal hostnames.
TLS_PORTS = (443, 8443, 993, 995, 465, 587, 636, 989, 990, 1443, 4443, 9443)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _cn(name) -> str | None:
    """First CN in an X.509 name, or None. Modern certs often omit CN entirely
    and carry everything in the SAN extension, so callers must tolerate None."""
    try:
        vals = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return str(vals[0].value).lower() if vals else None
    except Exception:
        return None


def _validity(cert) -> tuple:
    """(not_before, not_after) as timezone-aware UTC datetimes.

    cryptography renamed these to `*_utc` in 42 and deprecated the naive
    originals, so read the new names first and fall back — the extra asks for
    >=42 but a system install may well be older, and silently failing to parse
    a cert would be worse than a two-line shim.
    """
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return (cert.not_valid_before.replace(tzinfo=timezone.utc),
                cert.not_valid_after.replace(tzinfo=timezone.utc))


def parse_cert(der: bytes) -> dict | None:
    """Parse a DER certificate into the fields the report needs. Best-effort by
    design — a malformed cert returns None rather than raising into a scan."""
    if not HAVE_CRYPTO or not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = sorted({n.lower() for n in ext.value.get_values_for_type(x509.DNSName)})
    except Exception:
        pass                                       # no SAN extension, or unparseable
    not_before, not_after = _validity(cert)
    now = datetime.now(timezone.utc)
    return {
        "cn": _cn(cert.subject),
        "sans": sans,
        "issuer": _cn(cert.issuer) or _issuer_str(cert),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "days_to_expiry": (not_after - now).days,
        "self_signed": cert.issuer == cert.subject,
    }


def _issuer_str(cert) -> str | None:
    try:
        return cert.issuer.rfc4514_string()
    except Exception:
        return None


async def fetch_cert(host: str, port: int = 443, sni: str | None = None,
                     timeout: float = 6.0) -> dict | None:
    """Read the certificate a host serves. Returns None when unreachable, when
    the peer isn't TLS, or when `cryptography` isn't installed.

    SNI defaults to `host`, but is omitted for a bare IP: SNI carries a
    hostname, and sending an IP literal is invalid. That matters for origin
    discovery, where the point is to see the *default* cert an origin serves
    when it isn't being asked for a specific vhost.
    """
    if not HAVE_CRYPTO:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False                     # targets serve mismatched certs
    ctx.verify_mode = ssl.CERT_NONE                # ...and self-signed/expired ones
    server_hostname = sni if sni else (None if _is_ip(host) else host)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=server_hostname),
            timeout=timeout)
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return parse_cert(der)


def cert_names(cert: dict) -> list:
    """Every hostname the cert vouches for — SANs plus the CN. The CN is folded
    in because certs from older/internal CAs still put the only name there."""
    if not cert:
        return []
    names = list(cert.get("sans") or [])
    cn = cert.get("cn")
    if cn and cn not in names:
        names.append(cn)
    return names


def _covers(name: str, domain: str) -> bool:
    """Does a cert name cover `domain` or something inside it? Accepts the apex,
    any subdomain, and a `*.domain` wildcard."""
    name = (name or "").lstrip("*.").rstrip(".").lower()
    domain = (domain or "").rstrip(".").lower()
    if not name or not domain:
        return False
    return name == domain or name.endswith("." + domain)


def cert_matches_scope(cert: dict, domains) -> str | None:
    """The first cert name that falls inside scope, or None.

    Used as origin-IP confirmation: a cert naming the target on an IP that isn't
    Cloudflare's is strong evidence the IP is the real origin.
    """
    for name in cert_names(cert):
        if any(_covers(name, d) for d in domains):
            return name
    return None


def in_scope_cert_names(cert: dict, domains) -> list:
    """Concrete in-scope hostnames from a cert, for asset discovery.

    Wildcards are deliberately dropped: `*.x.com` is not a host you can resolve
    or probe, and adding it would put a non-name in the host table. Names
    outside scope are dropped too — a shared/CDN cert routinely carries other
    tenants' domains, which are not the client's assets and must never enter the
    report.
    """
    out = set()
    for name in cert_names(cert):
        if name.startswith("*") or "*" in name:
            continue
        if any(_covers(name, d) for d in domains):
            out.add(name.rstrip(".").lower())
    return sorted(out)
