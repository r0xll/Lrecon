from __future__ import annotations
import base64
import json
import re

# --------------------------------------------------------------------------- #
# Framework crypto-misconfig detection (BBOT badsecrets-style).
#
# `secrets.scan_text` finds secret-SHAPED strings; this finds exploitable
# framework crypto misconfigurations in a response LRecon already fetched. Every
# finding names a concrete, verifiable condition — never a guess — and stays a
# LEAD the operator confirms. Deliberately conservative: a signal we cannot
# soundly derive from a passive response (e.g. whether ASP.NET ViewState MAC is
# disabled, which needs the key to validate) is reported as a low-severity
# "test offline" pointer, not a high-severity RCE claim.
# --------------------------------------------------------------------------- #

_VIEWSTATE_RE = re.compile(r'name="__VIEWSTATE"', re.I)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_TELERIK_RE = re.compile(r"Telerik\.Web\.UI\.(?:DialogHandler|WebResource|SpellCheckHandler)", re.I)


def _b64json(seg: str) -> dict:
    """Decode a base64url JWT segment to a dict, or {} on any failure."""
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))
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


def _header_blob(headers) -> str:
    """"name: value" lines for every response header, or "" if headers can't be
    iterated. Accepts httpx.Headers or a plain dict (both expose .items())."""
    try:
        items = headers.items()
    except Exception:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in items)


def check_response(body: str, headers=None, cookies=None) -> list:
    """`[{kind, severity, detail}]` of framework crypto misconfigs in `body` +
    response `headers` + `cookies` (a list of Set-Cookie strings). Pure and
    keyless; deduped by kind. Tokens (JWTs) are searched across body, headers and
    cookies; the HTML-construct checks (ViewState, Telerik) look at the body."""
    body = body or ""
    # JWTs and bearer tokens routinely ride in headers/cookies, not just the body
    # — scan all three for the token checks (the header param used to be ignored).
    hay = "\n".join(p for p in (body, _header_blob(headers),
                                "\n".join(str(c) for c in (cookies or []))) if p)
    out = []

    # ASP.NET ViewState present. We cannot tell from a passive response whether
    # the MAC is disabled — that requires decoding/validating the ViewState with
    # the MachineKey — so this is a low-severity pointer to test offline, NOT an
    # RCE claim. (__VIEWSTATEGENERATOR presence/absence is not a MAC indicator.)
    if _VIEWSTATE_RE.search(body):
        out.append({"kind": "aspnet-viewstate", "severity": "low",
                    "detail": "ASP.NET ViewState present — decode offline to test for a "
                              "disabled MAC / known MachineKey (deserialization RCE class)"})

    if _TELERIK_RE.search(body):
        out.append({"kind": "telerik-ui", "severity": "medium",
                    "detail": "Telerik.Web.UI handler referenced — check the version for "
                              "CVE-2017-9248 / CVE-2019-18935 (known RCE/crypto bugs)"})

    out += _jwt_findings(hay)

    # Dedupe by kind (keep the first occurrence).
    seen, deduped = set(), []
    for f in out:
        if f["kind"] not in seen:
            seen.add(f["kind"])
            deduped.append(f)
    return deduped
