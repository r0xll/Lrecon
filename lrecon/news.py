from __future__ import annotations
import json
from .common import *
from . import llm

# --------------------------------------------------------------------------- #
# Factual company-intel enrichment for the dossier's Company Profile / recent-
# events section. FACTUAL SUMMARIZATION ONLY — this collects publicly filed /
# published items about the target company and has the LLM condense them into
# neutral, informational event buckets (m&a, exec-change, product, ...). It
# does NOT score items for "pretext potential" and does NOT generate lure /
# phishing content — that capability is intentionally excluded from lrecon
# (see README "Not built"). The output is company context a defender-side
# reviewer would want, nothing weaponized.
#
# Sources are operator-restrictable: SEC EDGAR full-text search (public, no
# key) plus any extra JSON/RSS endpoints the operator supplies via config.
# Every source is off unless reachable/configured; polite, low-volume.
# --------------------------------------------------------------------------- #

# SEC asks automated clients to send a descriptive UA; reuse lrecon's.
_EDGAR_UA = "lrecon/authorized-assessment"

_EVENT_BUCKETS = ("m&a", "exec-change", "product", "office-move",
                  "security-incident", "tech-migration", "other")


async def edgar_recent_filings(client, company: str, limiter=None, cap=10) -> list:
    """
    Recent SEC EDGAR full-text-search hits for a company name. Public, keyless.
    Returns a list of {title, form, date, url} (best-effort — EDGAR's schema
    shifts, so parse defensively and return [] on any miss). Only useful for
    US-registered entities; a no-match is normal, not an error.
    """
    if limiter:
        await limiter.wait()
    try:
        r = await client.get("https://efts.sec.gov/LATEST/search-index",
                            params={"q": f'"{company}"'},
                            headers={"User-Agent": _EDGAR_UA}, timeout=25)
        if r.status_code != 200:
            return []
        hits = (r.json() or {}).get("hits", {}).get("hits", []) or []
    except Exception as e:
        log(f"[!] edgar {company}: {e}")
        return []
    out = []
    for h in hits[:cap]:
        src = h.get("_source", {}) or {}
        adsh = (src.get("adsh") or "").replace("-", "")
        cik = (src.get("ciks") or [None])[0]
        url = (f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
               if cik else "https://www.sec.gov/cgi-bin/srqsb")
        out.append({"title": " ".join(src.get("display_names", [])) or company,
                    "form": src.get("file_type") or src.get("root_form") or "?",
                    "date": src.get("file_date") or "?",
                    "url": url, "adsh": adsh})
    return out


async def fetch_extra_sources(client, urls: list, limiter=None) -> list:
    """Operator-supplied JSON/RSS-ish endpoints (config `news.sources`). Each
    is fetched and its raw text handed to the summarizer as-is; lrecon does
    not scrape or crawl beyond the exact URLs given."""
    out = []
    for u in urls or []:
        if limiter:
            await limiter.wait()
        try:
            r = await client.get(u, headers={"User-Agent": _EDGAR_UA}, timeout=25)
            if r.status_code == 200:
                out.append({"url": u, "text": r.text[:8000]})
        except Exception as e:
            log(f"[!] news source {u}: {e}")
    return out


def _summary_prompt(company: str, domain: str, filings: list, extra: list) -> list:
    facts = {"company": company, "domain": domain,
             "sec_filings": filings,
             "other_sources": [{"url": e["url"], "excerpt": e["text"]} for e in extra]}
    system = (
        "You are a factual OSINT summarizer for an AUTHORIZED external "
        "reconnaissance report. Summarize only what the supplied public "
        "records state about the company. Produce neutral, informational "
        "company context for a security reviewer. Do NOT invent facts not "
        "present in the input. Do NOT write phishing, pretext, or social-"
        "engineering content, and do NOT rate anything for 'pretext "
        "potential' — that is out of scope. Respond ONLY with minified JSON."
    )
    user = (
        "From the public records below, produce JSON with keys: "
        '"summary" (2-4 sentence factual company overview), and "events" (a '
        "list of {\"bucket\", \"description\", \"date\", \"source\"} objects, "
        f"where bucket is one of {list(_EVENT_BUCKETS)}). Include only events "
        "actually evidenced in the input; use \"other\" for anything that "
        "doesn't fit a specific bucket. No commentary outside the JSON.\n\n"
        f"PUBLIC RECORDS:\n{json.dumps(facts)[:12000]}"
    )
    return [{"role": "system", "content": system},
            {"role": "user", "content": user}]


def _parse_summary(text: str) -> dict:
    """Extract the JSON object the model was asked for; tolerate code fences
    and leading/trailing prose. Returns {} if nothing parseable."""
    if not text:
        return {}
    s = text.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s.strip("`")
        if s.startswith("json"):
            s = s[4:]
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        data = json.loads(s[start:end + 1])
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    events = []
    for e in data.get("events", []) or []:
        if not isinstance(e, dict):
            continue
        bucket = e.get("bucket") if e.get("bucket") in _EVENT_BUCKETS else "other"
        events.append({"bucket": bucket, "description": e.get("description"),
                       "date": e.get("date"), "source": e.get("source")})
    return {"summary": data.get("summary"), "events": events}


async def company_intel(client, company: str, domain: str, llm_cfg,
                        extra_sources=None, limiter=None) -> dict:
    """
    Gather public company records (SEC EDGAR + operator-supplied sources) and
    have the LLM condense them into a neutral factual summary + event buckets.
    Returns {company, domain, summary, events, sources} — or a minimal record
    with empty summary/events if no LLM is reachable or nothing was found.
    """
    filings = await edgar_recent_filings(client, company, limiter=limiter)
    extra = await fetch_extra_sources(client, extra_sources, limiter=limiter)
    result = {"company": company, "domain": domain, "summary": None,
              "events": [], "sources": {"sec_filings": filings,
                                        "extra": [e["url"] for e in extra]}}
    if not filings and not extra:
        return result
    msgs = _summary_prompt(company, domain, filings, extra)
    out = await llm.complete(client, llm_cfg, msgs, module="news")
    parsed = _parse_summary(out or "")
    result["summary"] = parsed.get("summary")
    result["events"] = parsed.get("events", [])
    return result
