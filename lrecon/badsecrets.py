from __future__ import annotations
import base64
import re

# --------------------------------------------------------------------------- #
# Known-framework-secret / crypto-misconfig detection (BBOT badsecrets-style).
#
# `secrets.scan_text` finds secret-SHAPED strings; this finds exploitable
# framework misconfigurations in a response that LRecon already fetched — the
# high-signal class (unsigned ASP.NET ViewState, alg:none / known-key JWTs,
# an exposed Telerik dialog handler, a known default framework secret echoed in
# a cookie). Keyless, pure, and conservative: a finding names a concrete,
# verifiable condition, never a guess. Every finding is still a LEAD the
# operator confirms — the summaries say so.
# --------------------------------------------------------------------------- #

# A handful of HS256 secrets that ship as framework defaults or in popular
# tutorials/docs; a JWT that verifies against one of these is trivially forgeable.
# (We don't verify the signature here — that needs the HMAC — we only flag the
# obviously-dangerous shapes: alg:none, and the presence of a default secret
# string echoed server-side. Signature cracking is left to the operator.)
_KNOWN_DEFAULT_SECRETS = (
    "secret", "your-256-bit-secret", "your_jwt_secret", "changeme",
    "keyboard cat",                       # Express/connect default session secret
    "s3cr3t", "supersecret", "jwtsecret",
)

_VIEWSTATE_RE = re.compile(r'name="__VIEWSTATE"', re.I)
_VIEWSTATE_GEN_RE = re.compile(r'name="__VIEWSTATEGENERATOR"', re.I)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_TELERIK_RE = re.compile(r"Telerik\.Web\.UI\.(?:DialogHandler|WebResource|SpellCheckHandler)", re.I)


def _b64json(seg: str) -> dict:
    """Decode a base64url JWT segment to a dict, or {} on any failure."""
    try:
        pad = "=" * (-len(seg) % 4)
        return __import__("json").loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:
        return {}


def _jwt_findings(text: str) -> list:
    out = []
    for m in _JWT_RE.finditer(text or ""):
        tok = m.group(0)
        header = _b64json(tok.split(".", 1)[0])
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            out.append({"kind": "jwt-alg-none", "severity": "high",
                        "detail": "JWT with alg:none — signature not verified, trivially forgeable"})
        elif alg.startswith("hs"):
            # Can't crack the HMAC here, but a symmetric-signed JWT exposed in a
            # response is worth a weak-secret check by the operator.
            out.append({"kind": "jwt-hs-symmetric", "severity": "low",
                        "detail": f"JWT signed with {alg.upper()} exposed in response — "
                                  "test for a weak/default HMAC secret"})
    return out


def check_response(body: str, headers=None, cookies=None) -> list:
    """`[{kind, severity, detail}]` of known-framework-secret / crypto misconfigs
    in `body` + response `headers` + `cookies` (a list of Set-Cookie strings).
    Pure and keyless; deduped by kind."""
    body = body or ""
    hay = body
    if cookies:
        hay += "\n" + "\n".join(str(c) for c in cookies)
    out = []

    # ASP.NET ViewState present but with no generator token alongside it — a
    # common tell of MAC-disabled / unprotected ViewState (deserialization RCE).
    if _VIEWSTATE_RE.search(body) and not _VIEWSTATE_GEN_RE.search(body):
        out.append({"kind": "aspnet-viewstate-no-generator", "severity": "high",
                    "detail": "ASP.NET __VIEWSTATE present without __VIEWSTATEGENERATOR — "
                              "possible MAC-disabled ViewState (deserialization RCE); verify"})

    if _TELERIK_RE.search(body):
        out.append({"kind": "telerik-ui", "severity": "medium",
                    "detail": "Telerik.Web.UI handler referenced — check the version for "
                              "CVE-2017-9248 / CVE-2019-18935 (known RCE/crypto bugs)"})

    out += _jwt_findings(hay)

    # A known default framework secret echoed in a cookie/body (e.g. a session
    # signed with the Express/Flask/Rails default) — forgeable sessions.
    low = hay.lower()
    for sec in _KNOWN_DEFAULT_SECRETS:
        if sec in low:
            out.append({"kind": "known-default-secret", "severity": "medium",
                        "detail": f"known default framework secret '{sec}' present in "
                                  "response/cookies — sessions/tokens may be forgeable"})
            break

    # Dedupe by kind (keep the first/highest occurrence).
    seen, deduped = set(), []
    for f in out:
        if f["kind"] not in seen:
            seen.add(f["kind"])
            deduped.append(f)
    return deduped
