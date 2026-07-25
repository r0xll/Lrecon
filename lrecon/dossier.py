from __future__ import annotations
import json
from .common import *
from . import llm

# --------------------------------------------------------------------------- #
# Target dossier generator. Assembles a structured JSON + Markdown dossier from
# the data lrecon already collects (the `res` dict from core.run) plus optional
# factual news/company intel, and adds LLM-synthesized narrative sections on
# top of the raw structured facts. Machine-readable structured data is always
# preserved alongside the prose, so the JSON stays consumable even when no LLM
# is configured (narrative fields are simply null).
#
# Scope: reconnaissance dossier only — company profile, tech stack, entry
# points, and passive people OSINT. No pretext/lure generation and no active
# credential-oracle content (intentionally excluded from lrecon).
# --------------------------------------------------------------------------- #


def _collect_tech_stack(res: dict) -> dict:
    """Structured tech-stack facts pulled from what the pipeline already
    fingerprinted: live web tech, mail/collab provider, nameserver/DNS, and
    CPE-confirmed software."""
    hosts = res.get("hosts") or []
    tech = sorted({t for h in hosts for t in (getattr(h, "tech", None) or [])})
    servers = sorted({h.server for h in hosts if getattr(h, "server", None)})
    powered = sorted({h.powered_by for h in hosts if getattr(h, "powered_by", None)})
    confirmed = sorted({t for h in hosts if getattr(h, "tech_confirmed", None) is True
                        for t in (getattr(h, "tech", None) or [])})
    # mail_infra is keyed by domain -> list of MX entries
    mail = res.get("mail_infra") or {}
    providers = sorted({m.get("provider") for lst in mail.values()
                        for m in (lst or []) if m.get("provider")}) if isinstance(mail, dict) else []
    ns = sorted({n for d in (res.get("dns") or {}).values()
                 for n in (d.get("ns") or [])}) if isinstance(res.get("dns"), dict) else []
    return {"web_tech": tech, "web_tech_confirmed_live": confirmed,
            "servers": servers, "powered_by": powered,
            "mail_collab_providers": providers, "nameservers": ns}


def _collect_auth_surface(res: dict) -> list:
    out = []
    for a in (res.get("auth_surface") or []):
        out.append({"host": a.get("host"), "idp": a.get("idp"),
                    "issuer": a.get("issuer"), "oidc_config_url": a.get("oidc_config_url")})
    return out


def _collect_people(res: dict) -> list:
    out = []
    for p in (res.get("people") or []):
        d = p.to_dict() if hasattr(p, "to_dict") else dict(p)
        out.append({k: d.get(k) for k in
                    ("email", "name", "position", "confidence", "generated", "source")})
    return out


def _whois_org(res: dict) -> str | None:
    for w in (res.get("whois") or {}).values():
        org = w.get("registrant_org") or w.get("registrar")
        if org:
            return org
    return None


async def _narrative(client, llm_cfg, section: str, facts: dict) -> str | None:
    """One factual-synthesis LLM call for a dossier section. Returns None when
    no LLM is reachable so the section falls back to structured data only."""
    if not llm_cfg:
        return None
    system = (
        "You write concise, factual sections of an AUTHORIZED external "
        "reconnaissance dossier. Summarize only the structured findings "
        "provided; do not invent details. Do not produce phishing, pretext, "
        "or social-engineering content. Plain prose, 2-5 sentences, no "
        "preamble."
    )
    user = (f"Write the '{section}' section from these findings:\n"
            f"{json.dumps(facts, default=str)[:8000]}")
    return await llm.complete(client, llm_cfg, [{"role": "system", "content": system},
                                                {"role": "user", "content": user}],
                              module="dossier")


async def build_dossier(client, res: dict, domains: list, company_name: str | None,
                        llm_cfg=None, news: dict | None = None) -> dict:
    """
    Assemble the dossier from the collected `res` dict plus optional `news`
    company intel. Each section carries structured `data` and an optional
    LLM-synthesized `narrative`.
    """
    company = company_name or (domains[0].split(".")[0] if domains else "target")
    tech = _collect_tech_stack(res)
    auth = _collect_auth_surface(res)
    people = _collect_people(res)
    entry_points = res.get("entry_points") or []

    company_data = {"company": company, "domains": domains,
                    "registrant_org": _whois_org(res),
                    "news_summary": (news or {}).get("summary"),
                    "recent_events": (news or {}).get("events", [])}

    dossier = {
        "company": company,
        "domains": domains,
        "generated_with_llm": bool(llm_cfg),
        "company_profile": {"data": company_data,
                            "narrative": await _narrative(client, llm_cfg, "Company Profile", company_data)},
        "tech_stack": {"data": tech,
                       "narrative": await _narrative(client, llm_cfg, "Technology Stack", tech)},
        "entry_points": {"data": entry_points,
                         "narrative": await _narrative(client, llm_cfg, "Entry Points",
                                                       {"entry_points": entry_points}) if entry_points else None},
        "auth_surface": {"data": auth},
        "people": {"data": people},
    }
    return dossier


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
def write_dossier_json(dossier: dict, path: str) -> None:
    Path(path).write_text(json.dumps(dossier, indent=2, default=str))


def _md_list(items) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "_none found_"


def write_dossier_md(dossier: dict, path: str) -> None:
    L = [f"# Target dossier — {dossier.get('company')}", ""]
    L.append(f"**Domains:** {', '.join(dossier.get('domains') or []) or '—'}")
    if not dossier.get("generated_with_llm"):
        L.append("\n> Narrative synthesis was skipped (no LLM backend reachable); "
                 "structured findings only.")
    L.append("")

    cp = dossier.get("company_profile", {})
    L += ["## Company profile", ""]
    if cp.get("narrative"):
        L += [cp["narrative"], ""]
    cd = cp.get("data", {})
    if cd.get("registrant_org"):
        L.append(f"- **Registrant/registrar org:** {cd['registrant_org']}")
    for ev in cd.get("recent_events") or []:
        L.append(f"- **[{ev.get('bucket')}]** {ev.get('description')} "
                 f"({ev.get('date') or 'date n/a'})")
    L.append("")

    ts = dossier.get("tech_stack", {})
    td = ts.get("data", {})
    L += ["## Technology stack", ""]
    if ts.get("narrative"):
        L += [ts["narrative"], ""]
    L += ["**Web tech (live-detected):**", _md_list(td.get("web_tech")), "",
          "**Confirmed live (CPE-cross-checked):**", _md_list(td.get("web_tech_confirmed_live")), "",
          "**Mail / collaboration providers:**", _md_list(td.get("mail_collab_providers")), "",
          "**Servers:**", _md_list(td.get("servers")), ""]

    ep = dossier.get("entry_points", {})
    L += ["## Entry points", ""]
    if ep.get("narrative"):
        L += [ep["narrative"], ""]
    eps = ep.get("data") or []
    if eps:
        L += ["| Severity | Type | Target | Summary |", "|---|---|---|---|"]
        for e in eps:
            L.append(f"| {e.get('severity')} | {e.get('type')} | {e.get('target')} "
                     f"| {e.get('summary')} |")
    else:
        L.append("_none identified_")
    L.append("")

    au = dossier.get("auth_surface", {}).get("data") or []
    L += ["## Authentication surface (SSO/OIDC)", ""]
    if au:
        L += ["| Host | Identity provider | Issuer |", "|---|---|---|"]
        for a in au:
            L.append(f"| {a.get('host')} | {a.get('idp') or 'unknown'} | {a.get('issuer') or '—'} |")
    else:
        L.append("_no OIDC/SSO discovery endpoints found_")
    L.append("")

    ppl = dossier.get("people", {}).get("data") or []
    L += ["## People (passive OSINT)", ""]
    if ppl:
        L += ["| Email | Name | Position | Source |", "|---|---|---|---|"]
        for p in ppl:
            src = ", ".join(p.get("source") or []) if isinstance(p.get("source"), list) else p.get("source")
            L.append(f"| {p.get('email')} | {p.get('name') or '—'} | "
                     f"{p.get('position') or '—'} | {src or '—'} |")
    else:
        L.append("_none enumerated_")
    L.append("")

    Path(path).write_text("\n".join(L))
