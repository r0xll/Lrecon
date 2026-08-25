from __future__ import annotations
import re

# --------------------------------------------------------------------------- #
# Secret / credential patterns for JS-bundle scanning.
#
# Findings are LEADS, never assertions: a bundled key may be a public/publishable
# one (Firebase, a restricted Maps key), a placeholder, or a test fixture. Each
# match is masked (never the full secret in the report — the report itself would
# then carry it) and the operator verifies. Patterns are kept specific so the
# high-noise generic assignment rule below doesn't drown the strong ones.
# --------------------------------------------------------------------------- #
_PATTERNS = [
    ("aws-access-key",   re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key",   re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token",      re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("github-token",     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("stripe-secret-key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("jwt",              re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private-key",      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    # Deliberately last and lower-signal: an inline assignment to a
    # secret-ish name. Prone to false positives, so it only fires on a value
    # long enough to plausibly be a real credential.
    ("generic-secret-assignment",
     re.compile(r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password)"""
                r"""["']?\s*[:=]\s*["']([0-9A-Za-z_\-]{16,})["']""")),
]


def _mask(s: str) -> str:
    """Show enough to recognise a match without reproducing the secret."""
    s = s.strip()
    if len(s) <= 10:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


def scan_text(text: str, url: str = "") -> list:
    """Secret leads in `text`, as `[{kind, url, masked}]`, deduped by (kind, masked).

    Pure and side-effect-free so it is unit-testable and reusable (the JS scan
    now, the GitHub dork later). `url` is carried through as provenance only.
    """
    out, seen = [], set()
    for kind, rx in _PATTERNS:
        for m in rx.finditer(text or ""):
            # The generic rule captures the value in group 1; the strong rules
            # match the whole token.
            raw = m.group(1) if m.groups() else m.group(0)
            masked = _mask(raw)
            key = (kind, masked)
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": kind, "url": url, "masked": masked})
    return out
