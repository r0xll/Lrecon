from __future__ import annotations
import asyncio, csv, json
from datetime import datetime, timezone
from pathlib import Path
from .common import *
from .intel import DKIM_SELECTORS, SPF_MAX_LOOKUPS, mx_banner_suggestion
from .headers import header_gaps

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _md_code(value) -> str:
    """A DNS record as inline Markdown code, safe inside a table cell: records
    can contain `|` (rare) and are long enough to need the pipe escaped so the
    row doesn't break. Missing records render as an em dash, not empty."""
    if not value:
        return "— *(not published)*"
    return "`" + str(value).replace("|", "\\|") + "`"


# Kept generic: several signals now feed each level, so the label states the
# strength of the evidence and the per-host detail says which signal produced it.
TAKEOVER_CONFIDENCE_LABELS = {
    "confirmed": "confirmed — claimable at a known provider",
    "likely": "likely — unclaimed-service signature matched",
    "possible": "possible — unverified, see detail",
}
_TAKEOVER_CONFIDENCE_RANK = {"confirmed": 0, "likely": 1, "possible": 2}


def _by_takeover_confidence(hosts: list) -> list:
    """Highest-confidence takeover leads first — that's the order an operator
    works the list in. Unlabelled leads sort last but are never dropped."""
    return sorted(hosts, key=lambda h: (_TAKEOVER_CONFIDENCE_RANK.get(
        h.takeover_confidence, 3), h.subdomain))


def _axfr_has_result(r) -> bool:
    """Whether an AXFR attempt produced anything worth a section — including a
    nameserver that never resolved, which is a gap in its own right."""
    r = r or {}
    return bool(r.get("attempted") or r.get("transferred")
                or r.get("refused") or r.get("errors"))


def _md_emph_to_html(text: str) -> str:
    """Render the small Markdown subset used in shared status strings (`code`
    and **bold**) as HTML, escaping everything else. Lets both writers share one
    source of wording instead of maintaining two copies that can drift."""
    import html as _html, re as _re
    out, pos = [], 0
    for m in _re.finditer(r"\*\*(.+?)\*\*|`(.+?)`", text):
        out.append(_html.escape(text[pos:m.start()]))
        if m.group(1) is not None:
            out.append(f"<strong>{_html.escape(m.group(1))}</strong>")
        else:
            out.append(f"<code>{_html.escape(m.group(2))}</code>")
        pos = m.end()
    out.append(_html.escape(text[pos:]))
    return "".join(out)


_SPF_INCLUDE_FLAGS = {
    "nxdomain": ("does not exist", True),
    "no_spf": ("no SPF record", True),
    "lookup_failed": ("unchecked", False),
}


def _spf_include_health(e: dict) -> dict:
    """{target: state} for the includes diagnosed as unusable."""
    return {i["target"]: i["state"] for i in (e.get("spf_include_health") or [])}


def _spf_include_md(target: str, e: dict) -> str:
    """An `include:` or `redirect=` target, flagged inline when it's broken — the
    SPF breakdown is where a reader looks, so the defect belongs there and not
    only in Issues. Keyed on the target, so it serves both mechanisms."""
    state = _spf_include_health(e).get((target or "").lower().rstrip("."))
    label, bad = _SPF_INCLUDE_FLAGS.get(state, (None, False))
    if not label:
        return f"`{target}`"
    return f"`{target}` ({'**' + label + '**' if bad else label})"


def _split_people_by_kind(people: list) -> tuple:
    """(individuals, shared mailboxes). "How many of our users are exposed" is a
    headcount question, and `info@`/`noreply@` are not headcount."""
    from .people import ROLE_LOCALPARTS
    staff = [p for p in people if p.email.partition("@")[0] not in ROLE_LOCALPARTS]
    roles = [p for p in people if p.email.partition("@")[0] in ROLE_LOCALPARTS]
    return staff, roles


def _vt_origin_check_notes(vt: dict) -> list:
    """Why a domain has no origin candidates, when the reason isn't "none exist".

    An empty column reads as a clean result, and for a domain lrecon couldn't
    assess it isn't one — the check simply didn't run.
    """
    unknown = sorted(d for d, v in vt.items() if v.get("origin_check") == "unknown")
    not_fronted = sorted(d for d, v in vt.items() if v.get("origin_check") == "not_fronted")
    out = []
    if unknown:
        out.append(f"> Origin-candidate check **not run** for {', '.join(unknown)} — no live "
                   f"IPs to compare against (`--passive-only` skips resolution), so whether "
                   f"the domain is CDN-fronted is unknown. Absence of candidates here is not "
                   f"a clean result.")
    if not_fronted:
        out.append(f"> Origin-candidate check **not applicable** to "
                   f"{', '.join(not_fronted)} — not Cloudflare-fronted today, so a former "
                   f"address is a hosting change rather than a bypassable origin.")
    return out + [""] if out else []


def _vt_history_note(r: dict) -> str:
    """What a hosting-history row means, in a word. Blank when it means nothing
    in particular — a note on every row is a note on none of them."""
    if r.get("origin_candidate"):
        return "**origin candidate**"
    if r.get("cloudflare"):
        return "Cloudflare"
    return "—"


def _email_services(e: dict) -> list:
    """(kind, names) pairs for the third-party email services a domain reveals.

    Informational: which SaaS the org sends through, and who watches its DMARC
    reports. Never affects the grade — see phishing_posture()/the MTA-STS note.
    """
    out = []
    if e.get("spf_vendors"):
        out.append(("senders", e["spf_vendors"]))
    if e.get("dmarc_vendors"):
        out.append(("DMARC reporting", e["dmarc_vendors"]))
    gateway = (e.get("phishing_posture") or {}).get("gateway")
    if gateway:
        out.append(("inbound gateway", [gateway]))
    return out


def _mta_sts_text(e: dict) -> str:
    """MTA-STS state in one line. Absence is stated plainly rather than as a
    finding — most domains don't publish it, so it isn't a misconfiguration; a
    published-but-broken or non-enforcing policy is, and reads as such here."""
    if not e.get("mta_sts"):
        return "not published — SMTP TLS is downgradeable (STARTTLS stripping)"
    mode = e.get("mta_sts_mode")
    if e.get("mta_sts_policy") is None:
        return "record published but **policy file unreachable** — senders fall back to " \
               "opportunistic TLS"
    if mode == "enforce":
        return "`mode=enforce` — senders must use validated TLS"
    if mode in ("testing", "none"):
        return f"**`mode={mode}`** — published but not enforcing"
    # Fetched but with no usable mode — a catch-all page, or a malformed file.
    # Must not read as though a policy is in effect.
    return "policy file served but **invalid** (no usable `mode=`) — the published " \
           "record is not enforceable"


CERT_EXPIRY_SOON_DAYS = 30


def _cert_flags(c: dict) -> list:
    """Certificate conditions worth an operator's attention, worst first."""
    flags = []
    if c.get("expired"):
        flags.append("expired")
    if c.get("not_yet_valid"):
        flags.append("not yet valid")
    if c.get("self_signed"):
        flags.append("self-signed")
    days = c.get("days_to_expiry")
    if not c.get("expired") and isinstance(days, int) and days <= CERT_EXPIRY_SOON_DAYS:
        flags.append(f"expires in {days}d")
    return flags


def _cert_flags_md(c: dict) -> str:
    return ", ".join(f"**{f}**" for f in _cert_flags(c))


def _certs_by_risk(certs: list) -> list:
    """Flagged certificates first, then by endpoint — the table is read top-down
    and an expired or self-signed cert is the row that matters."""
    return sorted(certs, key=lambda c: (not _cert_flags(c), c.get("host") or "",
                                        c.get("port") or 0))


def _spf_lookups(sp: dict) -> tuple[str, str, str]:
    """`(count, caveat, level)` for the SPF DNS-lookup budget, where `level` is
    `"bad"` for a confirmed permerror, `"warn"` for a caveat that blocks a
    compliance claim, and `""` for a clean count.

    RFC 7208 §4.6.4's limit of 10 covers the lookups made inside every
    `include:`/`redirect=` target, so the figure is only meaningful with the
    caveat attached: a bare `n/10` would claim a complete accounting even when a
    nested lookup failed or expansion stopped early at the limit.
    """
    n = sp.get("lookup_count", 0)
    complete = sp.get("lookup_count_complete", True)
    exceeded = bool(sp.get("exceeds_lookup_limit"))
    # Counting stops as soon as the cap is passed, so an over-limit figure is a
    # lower bound — definitive as a verdict, but mark the number as "at least".
    count = f"{'≥' if exceeded and not complete else ''}{n}/{SPF_MAX_LOOKUPS}"
    if exceeded:
        return count, "exceeds limit (permerror)", "bad"
    if not complete:
        return count, "incomplete — an include: lookup failed, compliance unconfirmed", "warn"
    if sp.get("includes") or sp.get("redirect"):
        return count, "includes expanded", ""
    return count, "", ""



def _target_status(h) -> str:
    """Liveness of a host for the scope sheet.

    `live`    — answered the HTTP probe.
    `resolves`— has an IP but no HTTP response. Still a real target: SSH, VPN,
                mail and APIs all resolve without serving a web page, so this is
                deliberately not treated as dead.
    `unresolved` — no IP because resolution wasn't attempted (`--passive-only`).
    """
    if h.http_status:
        return "live"
    if h.ips:
        return "resolves"
    return "unresolved"


def write_csv(hosts, path) -> int:
    """Flat target list for client scope confirmation — one row per
    (subdomain, IP) pair (a multi-IP host repeats the subdomain, one row per
    IP, each with its own org, so every IP's org is directly visible).

    This is the sheet a client approves before testing starts, so it must not
    ask them to sign off on things that don't exist. Two exclusions:

      * **wildcard-suspect hosts** — DNS-wildcard enum artefacts, never real
        targets (the HTTP live list already drops these; this used not to).
      * **hosts that definitively do not exist** — `h.nxdomain`, i.e. the
        resolver returned NXDOMAIN. A name lrecon found in an old CT log that no
        longer resolves is noise on a scope sheet.

    The exclusion is keyed on a *confirmed* NXDOMAIN, not on an empty IP list: a
    timeout or SERVFAIL also leaves a host with no IPs but is inconclusive, and
    dropping it would silently pull a possibly-live target off the client's
    authorised scope — the one error worse than leaving a dead name in. Such a
    host stays with status `unresolved`. (`--passive-only` never resolves, so no
    host is ever nxdomain there and the full discovered list is kept.)

    Dead names are not lost — they remain in the report and JSON; they're just
    not promoted onto the approval sheet. A `status` column (live / resolves /
    unresolved) tells the client which rows have a live web service. Falls back
    to the scalar `h.org` only for single-IP hosts, where there's no ambiguity
    about which IP an org belongs to.
    """
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["subdomain", "ip", "org", "status"])
        n = 0
        for h in hosts:
            if h.wildcard or h.nxdomain:
                continue
            status = _target_status(h)
            if not h.ips:
                w.writerow([h.subdomain, "", "", status])
                n += 1
                continue
            single = len(h.ips) == 1
            for ip in h.ips:
                org = h.ip_org.get(ip) or (h.org if single else "") or ""
                w.writerow([h.subdomain, ip, org, status])
                n += 1
    return n


def write_users_csv(people, path) -> int:
    """
    Company-affiliated user enumeration (OSINT) output — a red-team phishing/
    password-spray candidate list. generated=True means the email is a
    pattern-applied guess (not directly observed); smtp_status is only
    populated with --verify-emails.
    """
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["email", "name", "position", "confidence", "generated",
                   "smtp_status", "source"])
        for p in people:
            w.writerow([p.email, p.name or "", p.position or "",
                       p.confidence if p.confidence is not None else "",
                       "yes" if p.generated else "",
                       p.smtp_status or "",
                       ", ".join(sorted(p.source))])
    return len(people)


def write_live_hosts(hosts, path) -> int:
    urls = []
    for h in hosts:
        if h.wildcard:
            continue
        if h.final_url:
            urls.append(h.final_url)
        elif h.http_status:
            urls.append(f"{h.scheme}://{h.subdomain}")
    urls = sorted(set(urls))
    Path(path).write_text("\n".join(urls) + ("\n" if urls else ""))
    return len(urls)


def write_origin_ips(cf, path) -> int:
    """
    Flat list of Cloudflare-origin-candidate IPs (confirmed + unconfirmed)
    for direct handoff to nmap/nuclei — the natural next step once a
    candidate is found is to scan it and see what Cloudflare was masking.
    Unconfirmed candidates are included too, not just confirmed ones: an
    active scan against the candidate is itself a stronger confirmation
    signal than the passive sourcing that put it on the list.
    """
    ips = sorted((cf or {}).get("candidates", {}).keys())
    Path(path).write_text("\n".join(ips) + ("\n" if ips else ""))
    return len(ips)


def _live_url(h) -> str:
    """The URL to hand a follow-up tool: the probe's final URL if it followed
    redirects, else scheme://subdomain."""
    return h.final_url or f"{h.scheme or 'https'}://{h.subdomain}"


def handoff_commands(hosts) -> list:
    """`[(host, [command, ...]), ...]` for each live, non-wildcard host, ordered
    by composite risk score (highest first) so the operator's next manual phase
    starts with the highest-value targets. Each host gets an nmap (service/version
    against its resolved IP or name, scoped to the ports already found), an ffuf
    content-discovery run, and a nuclei templated scan against the live URL.
    Every command is active and target-touching — a scaffold to review and run
    under ROE, never run from here."""
    live = [h for h in hosts if h.http_status and not h.wildcard]
    live.sort(key=lambda h: (-getattr(h, "risk_score", 0), h.subdomain))
    out = []
    for h in live:
        url = _live_url(h)
        target = h.ips[0] if h.ips else h.subdomain
        pflag = f"-p {','.join(str(p) for p in sorted(h.ports))} " if h.ports else ""
        cmds = [
            f"nmap -sV -Pn {pflag}{target}",
            f"ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 404",
            f"nuclei -u {url}",
        ]
        out.append((h, cmds))
    return out


def write_handoff(hosts, path) -> int:
    """Write a ready-to-run `<base>.handoff.sh` of per-live-host follow-up
    commands (see handoff_commands), ordered by risk. Returns the number of
    hosts covered."""
    packs = handoff_commands(hosts)
    lines = [
        "#!/usr/bin/env bash",
        "# LRecon handoff pack — follow-up commands for the next (manual) phase.",
        "# Every command below is ACTIVE and touches the target. Review each one and",
        "# run only within your authorized scope / rules of engagement. Hosts are",
        "# ordered by LRecon's composite risk score (highest first).",
        "set -u",
        "",
    ]
    for h, cmds in packs:
        lines.append(f"# ---- {h.subdomain}  (risk {getattr(h, 'risk_score', 0)}) ----")
        lines += cmds
        lines.append("")
    Path(path).write_text("\n".join(lines) + "\n")
    return len(packs)


def _whois_privacy_cell(w: dict) -> str:
    pp = w.get("privacy_protected")
    if pp is True:
        return "Yes"
    if pp is False:
        return "No"
    return "Unknown (not disclosed by registry)"


def _whois_registrant_cell(w: dict) -> str:
    pp = w.get("privacy_protected")
    if pp is True:
        provider = w.get("privacy_provider")
        return f"Privacy-protected ({provider})" if provider else "Privacy-protected"
    if pp is False:
        name, org = w.get("registrant_name"), w.get("registrant_org")
        if name and org and name != org:
            return f"{name} ({org})"
        return name or org or "—"
    return "—"


_WHOIS_SOURCE_LABELS = {"rdap": "RDAP", "whois43": "WHOIS (port 43)", "vt-whois": "VT WHOIS mirror"}


def _whois_source_label(source: str | None) -> str:
    if not source:
        return "—"
    return " + ".join(_WHOIS_SOURCE_LABELS.get(s, s) for s in source.split("+"))


def _tech_confirmed_label(h) -> str:
    if h.tech_confirmed is True:
        return "[tech-confirmed]"
    if h.tech_confirmed is False:
        return "[unconfirmed — verify]"
    return ""


def _exploit_summary(h):
    """`(kev_count, max_epss|None)` from a host's resolved CVEs — the real-world
    exploitability signals (CISA KEV membership, EPSS probability)."""
    nvd = getattr(h, "nvd_cves", None) or []
    kev_n = sum(1 for c in nvd if c.get("kev"))
    epss_v = [c["epss"] for c in nvd if c.get("epss") is not None]
    return kev_n, (max(epss_v) if epss_v else None)


def _format_ports_md(ports: list) -> str:
    """Bold any port outside WEB_PORTS — a non-HTTP service the probe
    pipeline never looks at, so it needs a manual look."""
    if not ports:
        return "—"
    nwp = set(non_web_ports(ports))
    return ", ".join(f"**{p}**" if p in nwp else str(p) for p in ports)


def _format_ports_html(ports: list) -> str:
    if not ports:
        return "—"
    nwp = set(non_web_ports(ports))
    return ", ".join(f'<span class="portflag" title="non-web service — needs manual review">{p}</span>'
                     if p in nwp else str(p) for p in ports)


def write_markdown(hosts, domains, res, path) -> None:
    per_source = res.get("per_source", {})
    cf = res.get("cf", {})
    entry_points = res.get("entry_points") or []
    live = [h for h in hosts if h.ips or h.http_status]
    vulns = [h for h in hosts if h.vulns]
    takeovers = [h for h in hosts if h.takeover]
    stale = [h for h in hosts if getattr(h, "stale_dns", None) and not h.takeover]
    wildcards = [h for h in hosts if h.wildcard]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# External Recon — {', '.join(domains)}", "",
        f"*Generated {ts} — authorized engagement. ATT&CK TA0043 Reconnaissance.*", "",
        f"- Subdomains discovered: **{len(hosts)}**",
        f"- Resolving / live: **{len(live)}**",
        f"- Hosts with reported CVEs: **{len(vulns)}**",
        f"- Subdomain-takeover leads: **{len(takeovers)}**",
        f"- Wildcard-suspect (filtered): **{len(wildcards)}**",
        f"- **Potential entry points: {len(entry_points)}**", "",
    ]

    if entry_points:
        lines += ["## ⚠ Potential entry points — chase these first", "",
                  "| Severity | Target | Finding | ATT&CK |", "|---|---|---|---|"]
        for e in entry_points:
            lines.append(f"| {e['severity'].upper()} | {e['target']} | {e['summary']} "
                         f"| {e.get('attck', '—')} |")
        lines += ["", "> Each row is a lead, not a confirmed compromise — validate per ROE "
                  "before treating as exploitable. Detail on each is in the sections below.", ""]
    else:
        lines += ["## Potential entry points", "",
                  "No high-confidence entry points identified from this pass "
                  "(passive/keyless sources only surface leads, not confirmations).", ""]

    heat = [h for h in hosts if getattr(h, "risk_score", 0) > 0]
    if heat:
        heat.sort(key=lambda h: (-h.risk_score, h.subdomain))
        lines += [f"## Attack-surface heat ({len(heat)})", "",
                  "Hosts ranked by a composite of the signals already collected — entry "
                  "points (severity-weighted), open non-web ports, missing WAF, and "
                  "security-header gaps. Score is capped at 100; the factors name every "
                  "contributor so the ranking is auditable. Work the top of this list first.",
                  "",
                  "| Score | Host | Factors |", "|---|---|---|"]
        for h in heat:
            lines.append(f"| {h.risk_score} | {h.subdomain} | "
                         f"{'; '.join(h.risk_factors) or '—'} |")
        lines.append("")

    if per_source:
        lines += ["## Passive source contribution", "",
                  "| Source | In-scope hosts found |", "|---|---|"]
        for s in sorted(per_source, key=lambda k: -per_source[k]):
            lines.append(f"| {s} | {per_source[s]} |")
        lines.append("")

    tracking = res.get("tracking_correlation") or {}
    if tracking:
        lines += [f"## Shared tracking IDs ({len(tracking)})", "",
                  "Analytics/marketing IDs (GA/GA4, GTM, Facebook Pixel) present on "
                  "**more than one** in-scope host. A shared ID means the pages are the "
                  "same team's assets — useful for confirming ownership and spotting "
                  "shadow-IT. Correlated within the scanned scope only; no third-party "
                  "lookup.", "",
                  "| Tracking ID | Hosts sharing it |", "|---|---|"]
        for tid in sorted(tracking):
            hs = tracking[tid]
            lines.append(f"| `{tid}` | {', '.join(hs)} |")
        lines.append("")

    ep_hosts = [h for h in hosts if getattr(h, "endpoints", None)]
    if ep_hosts:
        n_ep = sum(len(h.endpoints) for h in ep_hosts)
        lines += [f"## Discovered endpoints ({n_ep})", "",
                  "Live paths on in-scope hosts — archived paths (Wayback) that still "
                  "respond, exposed API docs, and source-map references. Forgotten admin "
                  "panels, old apps and API surface no passive source shows directly.", "",
                  "| Host | Path | Status | Source |", "|---|---|---|---|"]
        for h in ep_hosts:
            for ep in sorted(h.endpoints, key=lambda e: (e.get("status", 0), e.get("path", ""))):
                lines.append(f"| {h.subdomain} | {ep.get('path','')} | {ep.get('status','')} "
                             f"| {ep.get('source','')} |")
        lines.append("")

    sec_hosts = [h for h in hosts if getattr(h, "js_secrets", None)]
    if sec_hosts:
        n_sec = sum(len(h.js_secrets) for h in sec_hosts)
        lines += [f"## Secret leads in JS bundles ({n_sec})", "",
                  "Possible secrets found in same-origin JavaScript. **Leads, not "
                  "confirmations** — a bundled key may be publishable or a placeholder. "
                  "Values are masked; verify per ROE.", "",
                  "| Host | Kind | Value (masked) | Source URL |", "|---|---|---|---|"]
        for h in sec_hosts:
            for s in h.js_secrets:
                lines.append(f"| {h.subdomain} | {s.get('kind','')} | `{s.get('masked','')}` "
                             f"| {s.get('url','')} |")
        lines.append("")

    ban_hosts = [h for h in hosts if getattr(h, "banners", None)]
    if ban_hosts:
        n_ban = sum(len(h.banners) for h in ban_hosts)
        lines += [f"## Service banners ({n_ban})", "",
                  "Banners grabbed on open ports (SSH ident, TLS certificate, service "
                  "greeting) — service/version evidence for triage and CVE confirmation.", "",
                  "| Host | Port | Service | Banner |", "|---|---|---|---|"]
        for h in ban_hosts:
            for b in sorted(h.banners, key=lambda x: x.get("port", 0)):
                banner = str(b.get("banner", "")).replace("|", "\\|")
                lines.append(f"| {h.subdomain} | {b.get('port','')} | {b.get('service','')} "
                             f"| {banner} |")
        lines.append("")

    sh_rows = [(h, header_gaps(h.sec_headers, h.scheme or "https"))
               for h in hosts if getattr(h, "sec_headers", None)]
    sh_rows = [(h, g) for h, g in sh_rows if g]
    if sh_rows:
        lines += [f"## Security headers ({len(sh_rows)} host(s) with gaps)", "",
                  "Missing HTTP hardening headers and insecure cookie flags on live hosts "
                  "— defensive gaps, not initial-access vectors.", "",
                  "| Host | Missing / weak |", "|---|---|"]
        for h, gaps in sh_rows:
            lines.append(f"| {h.subdomain} | {'; '.join(gaps)} |")
        lines.append("")

    whois = res.get("whois") or {}
    if whois:
        lines += ["## Domain registration (WHOIS/RDAP)", "",
                  "| Domain | Registrar | Registrant | Privacy protected | Created | Expires | "
                  "Status | Nameservers | Source |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for d, w in whois.items():
            status = ", ".join(w.get("status", [])[:3]) or "—"
            ns = ", ".join(w.get("nameservers", [])[:4]) or "—"
            lines.append(f"| {d} | {w.get('registrar') or '—'} | {_whois_registrant_cell(w)} "
                         f"| {_whois_privacy_cell(w)} | {w.get('created') or '—'} "
                         f"| {w.get('expires') or '—'} | {status} | {ns} "
                         f"| {_whois_source_label(w.get('source'))} |")
        lines += ["", "> \"Unknown\" means either the registry-level RDAP response (and its "
                  "registrar referral, if any) didn't include a registrant entity at all — "
                  "common for some ccTLDs — or the lookup itself returned nothing for that "
                  "domain (unsupported TLD, typo, or a transient failure; see the run log). "
                  "Neither is a confirmed absence of privacy protection.",
                  "> RDAP has no service at all for some common TLDs (.io, .co, .me, and "
                  "others — confirmed against IANA's own bootstrap registry); those fall back "
                  "to classic WHOIS (port 43), whose free-text parsing is best-effort and "
                  "varies by registry.", ""]

        vt_all = res.get("vt") or {}
        vt_mirrors = {d: vt_all[d]["whois"] for d, w in whois.items()
                     if not w.get("registrar") and vt_all.get(d, {}).get("whois")}
        if vt_mirrors:
            lines += ["**VirusTotal WHOIS mirror** (unparsed, for manual cross-reference — "
                      "shown because no registrar was found above):", ""]
            for d, text in vt_mirrors.items():
                snippet = text[:2000] + ("…" if len(text) > 2000 else "")
                lines += [f"**{d}:**", "```", snippet, "```", ""]

    vt = res.get("vt") or {}
    if vt:
        lines += ["## Domain intelligence & IP/hosting history (VirusTotal)", "",
                  "| Domain | Reputation | VT malicious/suspicious votes | Creation date | "
                  "Last modified |", "|---|---|---|---|---|"]
        for d, v in vt.items():
            votes = f"{v.get('malicious_votes', 0)}/{v.get('suspicious_votes', 0)}"
            lines.append(f"| {d} | {v.get('reputation') if v.get('reputation') is not None else '—'} "
                         f"| {votes} | {v.get('creation_date') or '—'} "
                         f"| {v.get('last_modification_date') or '—'} |")
        lines.append("")
        any_history = any(v.get("ip_history") for v in vt.values())
        if any_history:
            lines += ["**Historical IP resolutions (hosting history)** — newest first:", "",
                      "| Domain | IP | First seen | Org | Country | Note |",
                      "|---|---|---|---|---|---|"]
            for d, v in vt.items():
                for r in (v.get("ip_history") or [])[:20]:
                    lines.append(f"| {d} | `{r['ip']}` | {r.get('first_seen') or '—'} "
                                 f"| {r.get('org') or '—'} "
                                 f"| {r.get('country') or '—'} | {_vt_history_note(r)} |")
            lines.append("")
            if any(r.get("origin_candidate") for v in vt.values()
                   for r in (v.get("ip_history") or [])):
                lines += ["> **Origin candidates** are addresses a *currently Cloudflare-fronted* "
                          "domain used to answer on directly — not Cloudflare themselves, and no "
                          "longer live for that domain. Worth a fetch with the target's `Host` "
                          "header to see whether the origin still serves there behind the CDN. "
                          "Treat as a lead: a shared host or a reassigned cloud address looks "
                          "the same from here.", ""]
            lines += _vt_origin_check_notes(vt)
        lines += ["> Free-tier VirusTotal domain intelligence — passive DNS history VT has "
                  "observed, not a live scan. A high malicious/suspicious vote count on a "
                  "client-owned domain is usually a false positive from prior compromise or "
                  "shared/CDN infrastructure; verify before reporting.", ""]

    dns_records = res.get("dns") or {}
    if dns_records:
        lines += ["## DNS records", "",
                  "| Domain | A | AAAA | MX | NS | SOA |", "|---|---|---|---|---|---|"]
        for d, r in dns_records.items():
            a = ", ".join(r.get("a", [])) or "—"
            aaaa = ", ".join(r.get("aaaa", [])) or "—"
            mx = ", ".join(f"{m['priority']} {m['host']}" for m in r.get("mx", [])) or "—"
            nsl = ", ".join(r.get("ns", [])) or "—"
            soa = r.get("soa") or "—"
            lines.append(f"| {d} | {a} | {aaaa} | {mx} | {nsl} | {soa} |")
        lines.append("")

    mail_infra = res.get("mail_infra") or {}
    if mail_infra:
        lines += ["## Mail infrastructure", "",
                  "| Domain | MX Host | Priority | IP(s) | Provider | ASN | Org | Country |",
                  "|---|---|---|---|---|---|---|---|"]
        for d, entries in mail_infra.items():
            for e in entries:
                ips = ", ".join(e.get("ips", [])) or "—"
                lines.append(f"| {d} | {e['host']} | {e['priority']} | {ips} | "
                             f"{e.get('provider') or 'self-hosted / unrecognized'} | "
                             f"{e.get('asn') or '—'} | {e.get('org') or '—'} | {e.get('country') or '—'} |")
        lines += ["", "> Managed email providers (Google Workspace, Microsoft 365, Proofpoint, etc.) "
                  "front spam/malware/phishing filtering; a self-hosted or unrecognized MX is worth "
                  "a closer look (SMTP banner grab, open relay, vulnerable MTA version) if in scope.", ""]

    if takeovers:
        lines += ["## Subdomain takeover leads (T1584.001) — priority", ""]
        for h in _by_takeover_confidence(takeovers):
            label = TAKEOVER_CONFIDENCE_LABELS.get(h.takeover_confidence)
            lines.append(f"- **{h.subdomain}** — {h.takeover}"
                         + (f"  *[{label}]*" if label else ""))
        lines += ["", "> Validate by attempting to claim the dangling resource in a "
                  "controlled manner per ROE before reporting as confirmed.", ""]

    if stale:
        lines += ["## Stale DNS records — broken, not claimable", ""]
        for h in sorted(stale, key=lambda x: x.subdomain):
            lines.append(f"- **{h.subdomain}** — {h.stale_dns}")
        lines += ["", "> Separated from the takeover leads on purpose: the target of each "
                  "record cannot be re-created by anyone, so there is nothing to claim. "
                  "These are hygiene findings — the record should be removed, but it is "
                  "not an attack path.", ""]

    if cf and cf.get("detected"):
        conf = {ip: v for ip, v in cf["candidates"].items() if v["confirmed"]}
        unconf = {ip: v for ip, v in cf["candidates"].items() if not v["confirmed"]}
        lines += ["## Cloudflare origin exposure — WAF/DDoS bypass",
                  "",
                  f"Cloudflare fronts {len(cf['fronted'])} in-scope host(s). "
                  f"Origin IPs reachable outside Cloudflare let an attacker bypass "
                  f"the WAF/DDoS layer entirely (origin IP disclosure).", ""]
        def _asn_org(v: dict) -> str:
            return " ".join(x for x in (v.get("asn"), v.get("org")) if x) or "unknown"

        if conf:
            lines += ["**Confirmed origin candidates** (responded to spoofed Host header):", ""]
            for ip, v in conf.items():
                lines.append(f"- `{ip}` ({_asn_org(v)}) — {v['evidence']} — "
                             f"sources: {', '.join(v['sources'])}")
            lines += ["",
                      "> Finding: Origin IP disclosure enabling WAF bypass. "
                      "CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) baseline — "
                      "raise if the origin exposes services CF was masking. "
                      "Remediation: restrict origin firewall to accept only Cloudflare IP "
                      "ranges (or use Authenticated Origin Pulls / cloudflared tunnel).", ""]
        if unconf:
            lines += ["**Unconfirmed candidate IPs** (found passively, not verified):", ""]
            for ip, v in unconf.items():
                lines.append(f"- `{ip}` ({_asn_org(v)}) — sources: {', '.join(v['sources'])}")
            lines.append("")

    diff = res.get("diff") or {}
    if diff and (diff.get("new_hosts") or diff.get("gone_hosts") or diff.get("new_ports")):
        lines += ["## Change since last run", "",
                  f"*Baseline: {diff.get('prev_ts', 'n/a')}*", ""]
        if diff.get("new_hosts"):
            lines.append(f"- **New hosts ({len(diff['new_hosts'])}):** "
                         + ", ".join(diff["new_hosts"][:40]))
        if diff.get("gone_hosts"):
            lines.append(f"- **Removed hosts ({len(diff['gone_hosts'])}):** "
                         + ", ".join(diff["gone_hosts"][:40]))
        if diff.get("new_ports"):
            for sub, ps in list(diff["new_ports"].items())[:20]:
                lines.append(f"- **{sub}** newly-open ports: {', '.join(map(str, ps))}")
        lines.append("")

    people = res.get("people") or []
    if people:
        staff, roles = _split_people_by_kind(people)
        lines += ["## People OSINT (user enumeration)", "",
                  f"**{len(staff)} individual-looking address(es)** and **{len(roles)} "
                  f"shared/role mailbox(es)** discovered. The split matters because a shared "
                  f"mailbox is exposure worth fixing but is not a person to phish or spray. "
                  f"Treat the first figure as a floor on exposed addresses rather than a "
                  f"headcount: only mailboxes matching lrecon's known role names are moved "
                  f"to the second column, so a mailing list or an alias still counts as "
                  f"individual until someone reads the list.", "",
                  "| Email | Name | Position | Kind | SMTP | Source |",
                  "|---|---|---|---|---|---|"]
        for p in staff + roles:
            kind = "shared/role" if p in roles else "individual"
            lines.append(f"| `{p.email}` | {p.name or '—'} | {p.position or '—'} | {kind} "
                         f"| {p.smtp_status or '—'} | {', '.join(sorted(p.source)) or '—'} |")
        lines += ["", "> Company-affiliated OSINT, not personal accounts. Addresses sourced "
                  "`website` were published by the target on its own pages. A `generated` "
                  "source is a pattern-applied guess, not an observed address — verify "
                  "before use.", ""]

    breach = res.get("breach") or {}
    if breach:
        lines += ["## Credential / breach exposure", ""]
        for d, bs in breach.items():
            for b in bs:
                dc = ", ".join(b.get("data", [])[:6])
                lines.append(f"- **{d}** — {b['name']} ({b.get('date','?')}, "
                             f"{b.get('pwned','?')} accounts): {dc}")
        lines += ["", "> Feeds password-spray candidate lists (T1110.003). "
                  "Cross-reference exposed accounts against valid users.", ""]

    gh = res.get("github") or []
    if gh:
        lines += ["## GitHub code exposure (T1593.003)", ""]
        for it in gh[:30]:
            lines.append(f"- `{it['repo']}` — {it['path']} — {it['url']}")
        lines += ["", "> Review each hit for leaked credentials, internal hostnames, "
                  "or keys. Public code referencing the target is an information-disclosure "
                  "finding worth triaging by hand.", ""]

    dorks = res.get("dorks") or []
    if dorks:
        lines += ["## Search-engine dork hits (T1593.002)", "",
                  "| Category | Severity | Title | Link |", "|---|---|---|---|"]
        for d in dorks:
            lines.append(f"| {d['category']} | {d['severity'].upper()} | {d['title']} | {d['link']} |")
        lines += ["", "> Google-indexed pages matching admin/login/config/backup dork "
                  "patterns for this domain — verify each is actually reachable and "
                  "exposed before reporting; a search-engine hit can be stale.", ""]

    buckets = res.get("buckets") or []
    if buckets:
        lines += ["## Cloud storage exposure", "",
                  "| Bucket | Provider | Status | Public listing | Objects | Sensitive | Size |",
                  "|---|---|---|---|---|---|---|"]
        for b in sorted(buckets, key=lambda x: not x["public"]):
            n_obj = b.get("object_count")
            n_int = len(b.get("interesting") or [])
            objs = (f"{n_obj}{'+' if b.get('truncated') else ''}"
                    if n_obj is not None else "—")
            lines.append(f"| [{b['name']}]({b['url']}) | {b['provider']} | {b['status']} | "
                         f"{'YES' if b['public'] else 'no'} | {objs} | "
                         f"{n_int or '—'} | {human_bytes(b.get('bytes')) if b.get('bytes') else '—'} |")

        # Per-bucket object detail — the actual red-team payload of this
        # section: direct links to what is exposed, sensitive-looking files
        # first, so the operator can triage without re-enumerating by hand.
        for b in [x for x in buckets if x.get("public") and x.get("objects")]:
            lines += ["", f"### `{b['name']}` ({b['provider']}) — "
                          f"{b.get('object_count', 0)} object(s)"
                          f"{', listing truncated by the provider' if b.get('truncated') else ''}", "",
                      f"Listing: <{b['url']}>", ""]
            interesting = b.get("interesting") or []
            if interesting:
                lines += ["**Sensitive-looking objects** (credentials/config/dumps/keys):", ""]
                for o in interesting[:25]:
                    lines.append(f"- [`{o['key']}`]({o['url']}) — {human_bytes(o.get('size'))}")
                if len(interesting) > 25:
                    lines.append(f"- …and {len(interesting) - 25} more")
                lines.append("")
            others = [o for o in b["objects"] if not o.get("interesting")]
            if others:
                lines += [f"<details><summary>Other objects ({len(others)})</summary>", ""]
                for o in others[:50]:
                    lines.append(f"- [`{o['key']}`]({o['url']}) — {human_bytes(o.get('size'))}")
                if len(others) > 50:
                    lines.append(f"- …and {len(others) - 50} more")
                lines += ["", "</details>", ""]

        if any(b["public"] for b in buckets):
            lines += ["", "> Public-listable buckets are a data-exposure finding. Object links "
                      "above come from the bucket's own listing response — lrecon does not "
                      "download contents; fetch only what your ROE permits.", ""]
        else:
            lines.append("")

    email = res.get("email") or {}
    if email:
        lines += ["## Email security posture", ""]
        for d, e in email.items():
            sp = e.get("spf_parsed") or {}
            dp = e.get("dmarc_parsed") or {}
            lines += [f"### {d} — **{e.get('grade','?')}**", ""]

            # Verbatim records first: the evidence a reviewer audits.
            lines += ["| Mechanism | Record |", "|---|---|"]
            lines.append(f"| SPF | {_md_code(e.get('spf'))} |")
            lines.append(f"| DMARC | {_md_code(e.get('dmarc'))} |")
            dkim_label = (f"DKIM (`{e['dkim_selector']}`)" if e.get("dkim_selector") else "DKIM")
            lines.append(f"| {dkim_label} | {_md_code(e.get('dkim_record'))} |")
            lines.append("")

            # Parsed breakdown — the analysis on top of the raw records.
            if e.get("spf"):
                q = sp.get("all_qualifier")
                qual = {"-": "-all (hard fail)", "~": "~all (soft fail)",
                        "?": "?all (neutral)", "+": "+all (pass-any!)"}.get(q, "no all mechanism")
                lk_count, lk_caveat, lk_level = _spf_lookups(sp)
                lines += [f"- **SPF policy:** {qual}",
                          f"- **SPF DNS lookups:** {lk_count}"
                          + (f"  ⚠️ {lk_caveat}" if lk_level
                             else f" *({lk_caveat})*" if lk_caveat else ""),
                          f"- **SPF includes ({len(sp.get('includes') or [])}):** "
                          + (", ".join(_spf_include_md(i, e) for i in sp["includes"])
                             if sp.get("includes") else "none")]
                if sp.get("ip4") or sp.get("ip6"):
                    nets = (sp.get("ip4") or []) + (sp.get("ip6") or [])
                    lines.append(f"- **SPF IP literals ({len(nets)}):** "
                                 + ", ".join(f"`{n}`" for n in nets[:12])
                                 + (f" +{len(nets) - 12} more" if len(nets) > 12 else ""))
                if sp.get("redirect"):
                    lines.append("- **SPF redirect:** "
                                 + _spf_include_md(sp["redirect"], e))
            if e.get("dmarc"):
                lines += [f"- **DMARC policy:** `p={dp.get('p') or '?'}`"
                          + (f", `sp={dp['sp']}`" if dp.get("sp") else "")
                          + (f", `pct={dp['pct']}`" if dp.get("pct") is not None else "")
                          + (f", `adkim={dp['adkim']}`" if dp.get("adkim") else "")
                          + (f", `aspf={dp['aspf']}`" if dp.get("aspf") else ""),
                          f"- **DMARC aggregate reports (rua):** "
                          + (", ".join(f"`{u}`" for u in dp["rua"]) if dp.get("rua") else "none")]
            if not e.get("dkim"):
                lines.append(f"- **DKIM:** not found on common selectors "
                             f"({', '.join(e.get('dkim_selectors_checked') or DKIM_SELECTORS)}) "
                             f"— inconclusive, a custom selector may exist")
            lines.append(f"- **MTA-STS:** {_mta_sts_text(e)}")
            lines.append(f"- **TLS-RPT:** "
                         + (f"`{e['tls_rpt']}`" if e.get("tls_rpt")
                            else "not published — no reporting of SMTP TLS failures"))
            lines.append(f"- **DANE/TLSA:** "
                         + (f"present on {', '.join(e['dane_mx'])}" if e.get("dane")
                            else "not published — MX certs not DNS-pinned"))
            mx_sugg = mx_banner_suggestion((res.get("mail_infra") or {}).get(d))
            if mx_sugg:
                lines.append(f"- **Recommendation:** {mx_sugg}")
            services = _email_services(e)
            if services:
                lines.append("- **Detected services:** "
                             + "; ".join(f"{k}: {', '.join(v)}" for k, v in services))
            lines.append("")

            posture = e.get("phishing_posture") or {}
            if posture.get("summary"):
                lines += [f"**Phishing posture:** {posture['summary']}", ""]

            issues = e.get("issues") or []
            lines += ["**Issues:**", ""]
            lines += [f"- {i}" for i in issues] if issues else ["- none"]
            lines.append("")
            notes = e.get("notes") or []
            if notes:
                lines += ["**Notes (advisory, grade-neutral):**", ""]
                lines += [f"- {n}" for n in notes] + [""]
            if e.get("lookup_errors"):
                lines += [f"> DNS lookups failed for this domain "
                          f"({'; '.join(e['lookup_errors'])}) — the affected mechanisms are "
                          f"**inconclusive**, not confirmed absent. Re-run with "
                          f"`--resolvers` pointing at a resolver that can return large "
                          f"TXT sets before reporting these as findings.", ""]
        lines += ["> SPF/DKIM/DMARC gaps enable email spoofing and strengthen "
                  "phishing pretext (relevant if the SOW covers social engineering).", ""]

    axfr = res.get("axfr") or {}
    if any(_axfr_has_result(v) for v in axfr.values()):
        lines += ["## DNS zone transfer (AXFR)", ""]
        for domain, r in axfr.items():
            r = r or {}
            if r.get("transferred"):
                for ns_host, count in r["transferred"].items():
                    lines.append(f"- **{domain}** — ⚠️ **transfer ALLOWED** by `{ns_host}`: "
                                 f"{count} record(s) disclosed")
                shown = r.get("records") or []
                if shown:
                    lines += ["", "<details><summary>Disclosed names "
                              f"({len(shown)} shown{', capped' if r.get('truncated') else ''})"
                              "</summary>", ""]
                    lines += [f"- `{n}`" for n in shown[:200]]
                    lines += ["", "</details>", ""]
            elif r.get("refused"):
                lines.append(f"- {domain} — refused by {len(r['refused'])} "
                             f"nameserver(s) (correctly restricted)")
            # Top-level bullets naming the domain: a nested item would lose its
            # list context after the <details> block above.
            for ns_host, err in (r.get("errors") or {}).items():
                lines.append(f"- {domain} — `{ns_host}`: **not conclusive** ({err}) "
                             f"— unreachable, not a refusal")
        lines += ["", "> A nameserver answering AXFR hands over every record in the zone "
                  "in one query, including internal-only names that no amount of "
                  "brute-forcing would surface. Restrict transfers to authorised "
                  "secondaries. An inconclusive result is a reachability problem, not "
                  "evidence that transfers are refused.", ""]

    stxt = res.get("security_txt") or []
    if stxt:
        lines += ["## security.txt (RFC 9116)", "",
                  "| Host | Contact | Expires | Policy |", "|---|---|---|---|"]
        for s in stxt:
            contact = ", ".join(s.get("contact") or [])[:120] or "—"
            exp = ", ".join(s.get("expires") or []) or "—"
            if s.get("expired"):
                exp += " ⚠️ **expired**"
            policy = ", ".join(s.get("policy") or [])[:120] or "—"
            lines.append(f"| `{s['host']}` | {contact} | {exp} | {policy} |")
        lines += ["", "> Names the disclosure channel a report should go to. The "
                  "`Policy`/`Canonical`/`Acknowledgments` URLs are worth following — they "
                  "routinely point at hosts nothing else surfaced. Per RFC 9116 an expired "
                  "`Expires` means the contact details should no longer be relied on.", ""]

    certs = res.get("certs") or []
    if certs:
        lines += ["## TLS certificates (as served)", "",
                  "| Endpoint | Subject CN | SANs | Issuer | Expires | Flags |",
                  "|---|---|---|---|---|---|"]
        for c in _certs_by_risk(certs):
            sans = c.get("sans") or []
            san_cell = ", ".join(f"`{s}`" for s in sans[:6]) or "—"
            if len(sans) > 6:
                san_cell += f" +{len(sans) - 6} more"
            lines.append(f"| `{c['host']}:{c['port']}` | `{c.get('cn') or '—'}` "
                         f"| {san_cell} | {c.get('issuer') or '—'} "
                         f"| {(c.get('not_after') or '—')[:10]} "
                         f"| {_cert_flags_md(c) or '—'} |")
        lines += ["", "> Read from the live handshake, so these are the certificates "
                  "actually presented — including ones never submitted to a CT log. "
                  "SAN entries inside scope are added to the host list as `tls-san`; "
                  "names belonging to other tenants on a shared certificate are "
                  "deliberately excluded.", ""]

    fp = res.get("favicon_pivots") or {}
    if fp:
        lines += ["## Favicon pivots (shadow assets sharing favicon)", ""]
        for fh, entry in fp.items():
            src = ", ".join(entry.get("sources") or []) or "seed domain"
            icon = (f'<img src="{entry["image"]}" width="20" alt="favicon"> '
                    if entry.get("image") else "")
            if entry.get("skipped"):
                lines.append(f"- {icon}hash `{fh}` (served by {src}) — **{entry['skipped']:,} "
                             f"matches**, too common to be a company marker (likely a "
                             f"framework/CDN default); skipped")
                continue
            matches = entry.get("matches") or []
            lines.append(f"- {icon}hash `{fh}` (served by {src}) — {len(matches)} host(s):")
            lines.append("")
            lines.append("| IP | Hostnames | Org | Cert CN | Title | Scope |")
            lines.append("|---|---|---|---|---|---|")
            for m in matches[:50]:
                names = ", ".join(m.get("hostnames") or []) or "—"
                scope = m.get("scope", "?") + (" · behind CF" if m.get("in_cf") else "")
                lines.append(f"| `{m['ip']}`"
                             + (f":{m['port']}" if m.get("port") else "")
                             + f" | {names} | {m.get('org') or '—'} | {m.get('cert_cn') or '—'} "
                             f"| {(m.get('title') or '—')[:60]} | {scope} |")
            lines.append("")
        lines += ["> A shared custom favicon is strong evidence of common ownership, but only "
                  "evidence — validate before reporting, and confirm SOW coverage before "
                  "touching any **cross-domain** host. Run with `--favicon-expand` to probe "
                  "those actively.", ""]

    nuclei = res.get("nuclei") or []
    if nuclei:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        nuclei = sorted(nuclei, key=lambda n: sev_order.get((n.get("severity") or "info"), 5))
        lines += ["## nuclei findings (templated vuln scan)", "",
                  "| Severity | Host | Template | CVE |", "|---|---|---|---|"]
        for n in nuclei:
            cve = n.get("cve") or "—"
            cve = ", ".join(cve) if isinstance(cve, list) else cve
            lines.append(f"| {(n.get('severity') or '?').upper()} | {n.get('host','?')} "
                         f"| {n.get('name') or n.get('template','?')} | {cve} |")
        crit = sum(1 for n in nuclei if n.get("severity") in ("critical", "high"))
        if crit:
            lines += ["", f"> {crit} high/critical finding(s) — validate and prioritise "
                      "for the deliverable. Each maps to a nuclei template with reproduction "
                      "at the matched URL.", ""]
        else:
            lines.append("")

    lines += ["## Attack surface", "",
              "| Subdomain | IP(s) | ASN / Org | Country | Open Ports | Tech | WAF/CDN | HTTP | CVEs |",
              "|---|---|---|---|---|---|---|---|---|"]
    for h in hosts:
        if h.wildcard:
            continue
        ips = ", ".join(h.ips) or "—"
        asn_org = " ".join(x for x in (h.asn, (h.org or "")[:20]) if x) or "—"
        ports = _format_ports_md(h.ports)
        tech = h.server or h.powered_by or (h.cpes[0] if h.cpes else "—")
        http = f"{h.scheme} {h.http_status}" if h.http_status else "—"
        v = ", ".join(h.vulns[:5]) + ("…" if len(h.vulns) > 5 else "") if h.vulns else "—"
        lines.append(f"| {h.subdomain} | {ips} | {asn_org} | {host_countries(h)} | {ports} "
                     f"| {tech} | {getattr(h, 'waf', None) or '—'} | {http} | {v} |")
    if any(non_web_ports(h.ports) for h in hosts if not h.wildcard):
        lines.append("")
        lines.append("> **Bold** ports are non-web services (SSH, RDP, databases, etc.) — the "
                     "HTTP probe never touches them, so they need a manual look.")

    if vulns:
        lines += ["", "## CVE hits (validate before reporting)", ""]
        for h in vulns:
            kev_n, max_epss = _exploit_summary(h)
            tag = (f" **[KEV×{kev_n}]**" if kev_n else "") + \
                  (f" [max EPSS {round(max_epss * 100)}%]" if max_epss is not None else "")
            lines.append(f"- **{h.subdomain}** ({', '.join(h.ips)}) {_tech_confirmed_label(h)}{tag}: "
                         f"{', '.join(h.vulns)}")
        engine = "Shodan" if any("shodan" in h.enrich_src for h in hosts) else "InternetDB"
        n_unconfirmed = sum(1 for h in vulns if h.tech_confirmed is False)
        lines += ["", f"> CVEs inferred from {engine} banner/version data. "
                  "Treat as leads, confirm with targeted validation."]
        if n_unconfirmed:
            lines.append(f"> {n_unconfirmed} host(s) marked \"unconfirmed\" — the live tech-detect "
                         "probe found no matching software for the reported CPE(s); the banner may "
                         "be stale or the service since patched/replaced. Triage confirmed hosts first.")

    packs = handoff_commands(hosts)
    if packs:
        lines += ["", f"## Handoff command pack ({len(packs)})", "",
                  "Ready-to-run follow-up commands for the next (manual) phase, ordered by "
                  "risk score. Every command is **active and touches the target** — review "
                  "and run only within your ROE. Also written to `<base>.handoff.sh`.", ""]
        for h, cmds in packs:
            lines += [f"**{h.subdomain}** (risk {getattr(h, 'risk_score', 0)})", "", "```sh"]
            lines += cmds
            lines += ["```", ""]

    Path(path).write_text("\n".join(lines) + "\n")



# --------------------------------------------------------------------------- #
# HTML report + optional screenshots
# --------------------------------------------------------------------------- #
def _html_section(section_id: str, title: str, count, body_html: str, open_default: bool = False) -> str:
    """One collapsible <details> section with an item-count badge in the summary."""
    badge = f' <span class="count">{count}</span>' if count is not None else ""
    open_attr = " open" if open_default else ""
    return (f'<details class="section" id="{section_id}"{open_attr}>'
            f'<summary>{title}{badge}</summary>'
            f'<div class="section-body">{body_html}</div></details>')


def _html_filter_toolbar(table_id: str) -> str:
    """Hint box, row counter and reset, directly above the filter row.

    The syntax used to be explained in a note *below* the table, which is not
    where anyone looks before typing into a box at the top. The counter is not
    decoration either: a filtered table looks exactly like a short one, and
    reading "12 hosts" off a table silently hiding 300 is the same class of
    mistake as a blocked source reporting 0.
    """
    return (
        f'<div class="filterhint">'
        f'<b>Filter:</b> type in a column box to narrow — any cell containing '
        f'what you type matches, so <code>20</code> finds 20, 2070 and 8020. '
        f'<code>443,8080</code> matches either &middot; '
        f'<code>!403</code> excludes &middot; '
        f'<code>!403,404</code> excludes both &middot; '
        f'<code>—</code> is an empty cell, so <code>!—</code> means "has one". '
        f'Columns combine with AND. Export CSV writes exactly the rows on screen.'
        f'</div>'
        f'<div class="filterbar"><span class="filtercount" '
        f'data-for="{table_id}"></span>'
        f'<button class="export-btn" type="button" '
        f'onclick="resetFilters(\'{table_id}\')">Reset filters</button></div>')


def _html_filter_row(columns: list) -> str:
    cells = "".join(
        f'<th class="filter-th"><input type="text" class="filter-input" '
        f'placeholder="{c}" aria-label="Filter by {c}"></th>' for c in columns)
    return f'<tr class="filter-row">{cells}</tr>'


def host_countries(h) -> str:
    """Every country a host's addresses sit in, not just the first one.

    `Host.country` is first-IP-wins, so a host balanced across regions reports
    one of them and looks like a single-country asset — which is exactly the
    wrong answer for the scoping and data-residency questions this column gets
    read for. The per-IP map is preferred when populated; `country` is the
    fallback for hosts enriched before it existed, or via a path that had no
    per-IP breakdown.
    """
    seen = sorted({c for c in (getattr(h, "ip_country", None) or {}).values() if c})
    return ", ".join(seen) or (h.country or "—")


def _html_export_button(table_id: str, filename: str) -> str:
    return (f'<button class="export-btn" type="button" '
            f'onclick="exportTableToCSV(\'{table_id}\',\'{filename}\')">Export CSV</button>')


SCREENSHOT_MAX_BYTES = 512 * 1024   # per-shot cap for the self-contained HTML


def write_html(hosts, domains, res, path, shots_dir=None) -> None:
    import html as _h

    def esc(x) -> str:
        return _h.escape(str(x)) if x not in (None, "") else "—"

    cf = res.get("cf") or {}
    entry_points = res.get("entry_points") or []
    per_source = res.get("per_source") or {}
    diff = res.get("diff") or {}
    breach = res.get("breach") or {}
    gh = res.get("github") or []
    buckets = res.get("buckets") or []
    email = res.get("email") or {}
    fp = res.get("favicon_pivots") or {}
    nuclei = res.get("nuclei") or []
    people = res.get("people") or []
    whois = res.get("whois") or {}
    dorks = res.get("dorks") or []
    dns_records = res.get("dns") or {}
    mail_infra = res.get("mail_infra") or {}
    vt = res.get("vt") or {}

    takeovers = [h for h in hosts if h.takeover]
    stale = [h for h in hosts if getattr(h, "stale_dns", None) and not h.takeover]
    vulns = [h for h in hosts if h.vulns]
    n_live = sum(1 for h in hosts if h.http_status)
    sev_class = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
                "low": "sev-low", "info": "sev-info"}

    def sev_badge(sev: str) -> str:
        sev = (sev or "info").lower()
        return f'<span class="sev {sev_class.get(sev, "sev-info")}">{esc(sev.upper())}</span>'

    sections = []

    # ---- Potential entry points ----
    if entry_points:
        rows = "".join(
            f"<tr><td>{sev_badge(e['severity'])}</td><td>{esc(e['target'])}</td>"
            f"<td>{esc(e['summary'])}</td><td>{esc(e.get('attck'))}</td></tr>"
            for e in entry_points)
        body = (f'{_html_export_button("t-entrypoints", "entry_points.csv")}'
                f'<table id="t-entrypoints"><tr><th>Severity</th><th>Target</th><th>Finding</th>'
                f'<th>ATT&amp;CK</th></tr>{rows}</table>'
                f'<p class="note">Leads, not confirmed compromises — validate per ROE '
                f'before treating as exploitable.</p>')
    else:
        body = '<p class="note">No high-confidence entry points identified from this pass.</p>'
    sections.append(_html_section("entrypoints", "⚠ Potential entry points", len(entry_points),
                                  body, open_default=True))

    # ---- Attack-surface heat (composite risk ranking) ----
    heat = [h for h in hosts if getattr(h, "risk_score", 0) > 0]
    if heat:
        heat.sort(key=lambda h: (-h.risk_score, h.subdomain))
        rows = "".join(
            f"<tr><td>{h.risk_score}</td><td>{esc(h.subdomain)}</td>"
            f"<td>{esc('; '.join(h.risk_factors))}</td></tr>"
            for h in heat)
        body = (f'{_html_export_button("t-heat", "attack_surface_heat.csv")}'
                f'<table id="t-heat"><tr><th>Score</th><th>Host</th><th>Factors</th></tr>{rows}</table>'
                f'<p class="note">Hosts ranked by a composite of signals already collected — '
                f'severity-weighted entry points, open non-web ports, missing WAF, and '
                f'security-header gaps (capped at 100). The factors name every contributor, so '
                f'the ranking is auditable. Work the top of this list first.</p>')
        sections.append(_html_section("heat", "Attack-surface heat", len(heat), body))

    # ---- Passive source contribution ----
    if per_source:
        rows = "".join(f"<tr><td>{esc(s)}</td><td>{per_source[s]}</td></tr>"
                       for s in sorted(per_source, key=lambda k: -per_source[k]))
        body = (f'<table id="t-sources"><tr><th>Source</th><th>In-scope hosts found</th></tr>{rows}</table>')
        sections.append(_html_section("sources", "Passive source contribution", len(per_source), body))

    # ---- Shared tracking IDs (in-scope analytics correlation) ----
    tracking = res.get("tracking_correlation") or {}
    if tracking:
        rows = "".join(
            f"<tr><td><code>{esc(tid)}</code></td><td>{esc(', '.join(tracking[tid]))}</td></tr>"
            for tid in sorted(tracking))
        body = (f'{_html_export_button("t-tracking", "tracking_ids.csv")}'
                f'<table id="t-tracking"><tr><th>Tracking ID</th><th>Hosts sharing it</th>'
                f'</tr>{rows}</table>'
                f'<p class="note">Analytics/marketing IDs (GA/GA4, GTM, Facebook Pixel) on '
                f'<strong>more than one</strong> in-scope host — shared ID means shared owner, '
                f'useful for confirming ownership and spotting shadow-IT. Correlated within the '
                f'scanned scope only; no third-party lookup.</p>')
        sections.append(_html_section("tracking", "Shared tracking IDs", len(tracking), body))

    # ---- Discovered endpoints (Wayback + API docs -> live) ----
    ep_hosts = [h for h in hosts if getattr(h, "endpoints", None)]
    if ep_hosts:
        n_ep = sum(len(h.endpoints) for h in ep_hosts)
        rows = "".join(
            f"<tr><td>{esc(h.subdomain)}</td><td>{esc(ep.get('path'))}</td>"
            f"<td>{esc(ep.get('status'))}</td><td>{esc(ep.get('source'))}</td></tr>"
            for h in ep_hosts
            for ep in sorted(h.endpoints, key=lambda e: (e.get("status", 0), e.get("path", ""))))
        body = (f'{_html_export_button("t-endpoints", "endpoints.csv")}'
                f'<table id="t-endpoints"><tr><th>Host</th><th>Path</th><th>Status</th>'
                f'<th>Source</th></tr>{rows}</table>'
                f'<p class="note">Live paths on in-scope hosts — archived (Wayback) paths that '
                f'still respond, exposed API docs, and source-map references. Validate per ROE.</p>')
        sections.append(_html_section("endpoints", "Discovered endpoints", n_ep, body))

    # ---- Secret leads in JS bundles ----
    sec_hosts = [h for h in hosts if getattr(h, "js_secrets", None)]
    if sec_hosts:
        n_sec = sum(len(h.js_secrets) for h in sec_hosts)
        rows = "".join(
            f"<tr><td>{esc(h.subdomain)}</td><td>{esc(s.get('kind'))}</td>"
            f"<td><code>{esc(s.get('masked'))}</code></td><td>{esc(s.get('url'))}</td></tr>"
            for h in sec_hosts for s in h.js_secrets)
        body = (f'{_html_export_button("t-jssecrets", "js_secrets.csv")}'
                f'<table id="t-jssecrets"><tr><th>Host</th><th>Kind</th><th>Value (masked)</th>'
                f'<th>Source URL</th></tr>{rows}</table>'
                f'<p class="note">Possible secrets in same-origin JavaScript — <strong>leads, '
                f'not confirmations</strong>. A bundled key may be publishable or a placeholder. '
                f'Values masked; verify per ROE.</p>')
        sections.append(_html_section("jssecrets", "Secret leads in JS bundles", n_sec, body))

    # ---- Service banners ----
    ban_hosts = [h for h in hosts if getattr(h, "banners", None)]
    if ban_hosts:
        n_ban = sum(len(h.banners) for h in ban_hosts)
        rows = "".join(
            f"<tr><td>{esc(h.subdomain)}</td><td>{esc(b.get('port'))}</td>"
            f"<td>{esc(b.get('service'))}</td><td><code>{esc(b.get('banner'))}</code></td></tr>"
            for h in ban_hosts
            for b in sorted(h.banners, key=lambda x: x.get("port", 0)))
        body = (f'{_html_export_button("t-banners", "banners.csv")}'
                f'<table id="t-banners"><tr><th>Host</th><th>Port</th><th>Service</th>'
                f'<th>Banner</th></tr>{rows}</table>'
                f'<p class="note">Banners on open ports (SSH ident, TLS cert, service '
                f'greeting) — service/version evidence for triage and CVE confirmation.</p>')
        sections.append(_html_section("banners", "Service banners", n_ban, body))

    # ---- Security headers ----
    sh_rows = [(h, header_gaps(h.sec_headers, h.scheme or "https"))
               for h in hosts if getattr(h, "sec_headers", None)]
    sh_rows = [(h, g) for h, g in sh_rows if g]
    if sh_rows:
        rows = "".join(
            f"<tr><td>{esc(h.subdomain)}</td><td>{esc('; '.join(gaps))}</td></tr>"
            for h, gaps in sh_rows)
        body = (f'{_html_export_button("t-secheaders", "security_headers.csv")}'
                f'<table id="t-secheaders"><tr><th>Host</th><th>Missing / weak</th></tr>'
                f'{rows}</table>'
                f'<p class="note">Missing HTTP hardening headers and insecure cookie flags '
                f'on live hosts — defensive gaps, not initial-access vectors.</p>')
        sections.append(_html_section("secheaders", "Security headers", len(sh_rows), body))

    # ---- Domain registration (WHOIS/RDAP) ----
    if whois:
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(w.get('registrar'))}</td>"
            f"<td>{esc(_whois_registrant_cell(w))}</td><td>{esc(_whois_privacy_cell(w))}</td>"
            f"<td>{esc(w.get('created'))}</td>"
            f"<td>{esc(w.get('expires'))}</td><td>{esc(', '.join(w.get('status', [])[:3]))}</td>"
            f"<td>{esc(', '.join(w.get('nameservers', [])[:4]))}</td>"
            f"<td>{esc(_whois_source_label(w.get('source')))}</td></tr>"
            for d, w in whois.items())
        body = (f'{_html_export_button("t-whois", "whois.csv")}'
                f'<table id="t-whois"><tr><th>Domain</th><th>Registrar</th><th>Registrant</th>'
                f'<th>Privacy protected</th><th>Created</th>'
                f'<th>Expires</th><th>Status</th><th>Nameservers</th><th>Source</th></tr>{rows}</table>'
                f'<p class="note">"Unknown" means either the registry-level RDAP response (and '
                f'its registrar referral, if any) didn\'t include a registrant entity at all — '
                f'common for some ccTLDs — or the lookup itself returned nothing for that '
                f'domain (unsupported TLD, typo, or a transient failure; see the run log). '
                f'Neither is a confirmed absence of privacy protection.</p>'
                f'<p class="note">RDAP has no service at all for some common TLDs (.io, .co, '
                f'.me, and others — confirmed against IANA\'s own bootstrap registry); those '
                f'fall back to classic WHOIS (port 43), whose free-text parsing is best-effort '
                f'and varies by registry.</p>')
        vt_mirrors = {d: vt[d]["whois"] for d, w in whois.items()
                     if not w.get("registrar") and vt.get(d, {}).get("whois")}
        if vt_mirrors:
            mirror_html = "".join(
                f'<details><summary>{esc(d)}</summary><pre>{esc(text[:2000])}'
                f'{"…" if len(text) > 2000 else ""}</pre></details>'
                for d, text in vt_mirrors.items())
            body += (f'<p><b>VirusTotal WHOIS mirror</b> (unparsed, for manual cross-reference — '
                     f'shown because no registrar was found above):</p>{mirror_html}')
        sections.append(_html_section("whois", "Domain registration (WHOIS/RDAP)", len(whois), body))

    # ---- VirusTotal domain intelligence + IP/hosting history ----
    if vt:
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(v.get('reputation'))}</td>"
            f"<td>{esc(v.get('malicious_votes', 0))}/{esc(v.get('suspicious_votes', 0))}</td>"
            f"<td>{esc(v.get('creation_date'))}</td><td>{esc(v.get('last_modification_date'))}</td></tr>"
            for d, v in vt.items())
        body = (f'{_html_export_button("t-vt", "vt_domain_intel.csv")}'
                f'<table id="t-vt"><tr><th>Domain</th><th>Reputation</th>'
                f'<th>VT malicious/suspicious votes</th><th>Creation date</th>'
                f'<th>Last modified</th></tr>{rows}</table>')
        def _hist_note_html(r: dict) -> str:
            if r.get("origin_candidate"):
                return '<strong class="bad">origin candidate</strong>'
            return "Cloudflare" if r.get("cloudflare") else "—"

        history_rows = "".join(
            f"<tr><td>{esc(d)}</td><td><code>{esc(r['ip'])}</code></td>"
            f"<td>{esc(r.get('first_seen'))}</td>"
            f"<td>{esc(r.get('org') or '—')}</td><td>{esc(r.get('country') or '—')}</td>"
            f"<td>{_hist_note_html(r)}</td></tr>"
            for d, v in vt.items() for r in (v.get("ip_history") or [])[:20])
        if history_rows:
            body += (f'<p><b>Historical IP resolutions (hosting history)</b> — newest first:</p>'
                     f'{_html_export_button("t-vt-history", "vt_ip_history.csv")}'
                     f'<table id="t-vt-history"><tr><th>Domain</th><th>IP</th>'
                     f'<th>First seen</th><th>Org</th><th>Country</th>'
                     f'<th>Note</th></tr>{history_rows}</table>')
            if any(r.get("origin_candidate") for v in vt.values()
                   for r in (v.get("ip_history") or [])):
                body += ('<p class="note"><b>Origin candidates</b> are addresses a <i>currently '
                         'Cloudflare-fronted</i> domain used to answer on directly — not '
                         'Cloudflare themselves, and no longer live for that domain. Worth a '
                         'fetch with the target\'s Host header to see whether the origin still '
                         'serves there behind the CDN. Treat as a lead: a shared host or a '
                         'reassigned cloud address looks the same from here.</p>')
            for note in _vt_origin_check_notes(vt):
                if note:
                    body += f'<p class="note">{esc(note.lstrip("> ")).replace("**", "")}</p>'
        body += ('<p class="note">Free-tier VirusTotal domain intelligence — passive DNS '
                 'history VT has observed, not a live scan. A high malicious/suspicious vote '
                 'count on a client-owned domain is usually a false positive from prior '
                 'compromise or shared/CDN infrastructure; verify before reporting.</p>')
        n_history = sum(len(v.get("ip_history") or []) for v in vt.values())
        sections.append(_html_section("vt", "Domain intelligence & IP/hosting history (VirusTotal)",
                                      len(vt) + n_history, body))

    # ---- DNS records ----
    if dns_records:
        def _mx_str(r):
            return ", ".join(f"{m['priority']} {m['host']}" for m in r.get("mx", []))
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(', '.join(r.get('a', [])))}</td>"
            f"<td>{esc(', '.join(r.get('aaaa', [])))}</td>"
            f"<td>{esc(_mx_str(r))}</td>"
            f"<td>{esc(', '.join(r.get('ns', [])))}</td><td>{esc(r.get('soa'))}</td></tr>"
            for d, r in dns_records.items())
        body = (f'{_html_export_button("t-dns", "dns_records.csv")}'
                f'<table id="t-dns"><tr><th>Domain</th><th>A</th><th>AAAA</th><th>MX</th>'
                f'<th>NS</th><th>SOA</th></tr>{rows}</table>')
        sections.append(_html_section("dns", "DNS records", len(dns_records), body))

    # ---- Mail infrastructure ----
    if mail_infra:
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(e['host'])}</td><td>{esc(e['priority'])}</td>"
            f"<td>{esc(', '.join(e.get('ips', [])))}</td>"
            f"<td>{esc(e.get('provider') or 'self-hosted / unrecognized')}</td>"
            f"<td>{esc(e.get('asn'))}</td><td>{esc(e.get('org'))}</td><td>{esc(e.get('country'))}</td></tr>"
            for d, entries in mail_infra.items() for e in entries)
        n_infra = sum(len(v) for v in mail_infra.values())
        body = (f'{_html_export_button("t-mailinfra", "mail_infrastructure.csv")}'
                f'<table id="t-mailinfra"><tr><th>Domain</th><th>MX Host</th><th>Priority</th>'
                f'<th>IP(s)</th><th>Provider</th><th>ASN</th><th>Org</th><th>Country</th></tr>{rows}</table>'
                f'<p class="note">Self-hosted or unrecognized MX hosts are worth a closer look '
                f'(SMTP banner grab, open relay, vulnerable MTA version) if in scope.</p>')
        sections.append(_html_section("mailinfra", "Mail infrastructure", n_infra, body))

    # ---- Subdomain takeover leads ----
    if takeovers:
        def _conf_cell(h) -> str:
            label = TAKEOVER_CONFIDENCE_LABELS.get(h.takeover_confidence)
            if not label:
                return '<td class="note">unlabelled</td>'
            cls = "bad" if h.takeover_confidence in ("confirmed", "likely") else "warn"
            return f'<td><strong class="{cls}">{esc(label)}</strong></td>'

        rows = "".join(f"<tr><td>{esc(h.subdomain)}</td>{_conf_cell(h)}"
                       f"<td>{esc(h.takeover)}</td></tr>"
                       for h in _by_takeover_confidence(takeovers))
        body = (f'{_html_export_button("t-takeover", "takeover_leads.csv")}'
                f'<table id="t-takeover"><tr><th>Subdomain</th><th>Confidence</th>'
                f'<th>Detail</th></tr>{rows}</table>'
                f'<p class="note">Validate by attempting to claim the dangling resource in a '
                f'controlled manner per ROE before reporting as confirmed.</p>')
        sections.append(_html_section("takeover", "Subdomain takeover leads (T1584.001)",
                                      len(takeovers), body))

    # ---- Stale DNS: broken, but provably not claimable ----
    if stale:
        rows = "".join(f"<tr><td>{esc(h.subdomain)}</td><td>{esc(h.stale_dns)}</td></tr>"
                       for h in sorted(stale, key=lambda x: x.subdomain))
        body = (f'{_html_export_button("t-stale", "stale_dns.csv")}'
                f'<table id="t-stale"><tr><th>Subdomain</th><th>Detail</th></tr>'
                f'{rows}</table>'
                f'<p class="note">Kept out of the takeover leads deliberately: the target of '
                f'each record cannot be re-created by anyone, so there is nothing to claim. '
                f'The record should be removed, but it is not an attack path.</p>')
        sections.append(_html_section("staledns", "Stale DNS records — broken, not claimable",
                                      len(stale), body))

    # ---- Cloudflare origin exposure ----
    if cf.get("detected"):
        conf = {ip: v for ip, v in cf["candidates"].items() if v["confirmed"]}
        unconf = {ip: v for ip, v in cf["candidates"].items() if not v["confirmed"]}

        def _asn_org_html(v: dict) -> str:
            return esc(" ".join(x for x in (v.get("asn"), v.get("org")) if x) or "unknown")

        body = (f'<p>Cloudflare fronts {len(cf["fronted"])} in-scope host(s). Origin IPs reachable '
                f'outside Cloudflare let an attacker bypass the WAF/DDoS layer entirely.</p>')
        if conf:
            rows = "".join(f'<tr><td><code>{esc(ip)}</code></td><td>{_asn_org_html(v)}</td>'
                          f'<td>{esc(v["evidence"])}</td>'
                          f'<td>{esc(", ".join(v["sources"]))}</td></tr>' for ip, v in conf.items())
            body += (f'<p><b>Confirmed origin candidates</b> (responded to spoofed Host header):</p>'
                     f'<table id="t-cforigin"><tr><th>IP</th><th>ASN/Org</th><th>Evidence</th>'
                     f'<th>Sources</th></tr>{rows}</table>')
        if unconf:
            rows = "".join(f'<tr><td><code>{esc(ip)}</code></td><td>{_asn_org_html(v)}</td>'
                          f'<td>{esc(", ".join(v["sources"]))}</td></tr>'
                          for ip, v in unconf.items())
            body += (f'<p><b>Unconfirmed candidate IPs</b> (found passively, not verified):</p>'
                     f'<table><tr><th>IP</th><th>ASN/Org</th><th>Sources</th></tr>{rows}</table>')
        sections.append(_html_section("cforigin", "Cloudflare origin exposure",
                                      len(cf["candidates"]), body))

    # ---- Change since last run ----
    if diff and (diff.get("new_hosts") or diff.get("gone_hosts") or diff.get("new_ports")):
        n_changed = (len(diff.get("new_hosts") or []) + len(diff.get("gone_hosts") or [])
                    + len(diff.get("new_ports") or {}))
        body = f'<p class="note">Baseline: {esc(diff.get("prev_ts"))}</p><ul>'
        if diff.get("new_hosts"):
            body += f'<li><b>New hosts ({len(diff["new_hosts"])}):</b> {esc(", ".join(diff["new_hosts"][:40]))}</li>'
        if diff.get("gone_hosts"):
            body += f'<li><b>Removed hosts ({len(diff["gone_hosts"])}):</b> {esc(", ".join(diff["gone_hosts"][:40]))}</li>'
        for sub, ps in list((diff.get("new_ports") or {}).items())[:20]:
            body += f'<li><b>{esc(sub)}</b> newly-open ports: {esc(", ".join(map(str, ps)))}</li>'
        body += "</ul>"
        sections.append(_html_section("diff", "Change since last run", n_changed, body))

    # ---- People OSINT / enumerated users ----
    if people:
        staff, roles = _split_people_by_kind(people)
        role_emails = {p.email for p in roles}
        rows = "".join(
            f"<tr><td>{esc(p.email)}</td><td>{esc(p.name)}</td><td>{esc(p.position)}</td>"
            f"<td>{'shared/role' if p.email in role_emails else 'individual'}</td>"
            f"<td>{esc(p.confidence)}</td><td>{'yes' if p.generated else ''}</td>"
            f"<td>{esc(p.smtp_status)}</td><td>{esc(', '.join(sorted(p.source)))}</td></tr>"
            for p in staff + roles)
        body = (f'{_html_export_button("t-people", "users.csv")}'
                f'<p><b>{len(staff)}</b> individual-looking address(es), <b>{len(roles)}</b> '
                f'shared/role mailbox(es). Only known role names are split out, so a mailing '
                f'list or alias still counts as individual — treat the first figure as a '
                f'floor on exposed addresses, not a headcount.</p>'
                f'<table id="t-people"><tr><th>Email</th><th>Name</th><th>Position</th>'
                f'<th>Kind</th><th>Confidence</th><th>Generated</th><th>SMTP status</th>'
                f'<th>Source</th></tr>'
                f'{rows}</table>'
                f'<p class="note">Company-affiliated OSINT, not personal accounts. '
                f'Addresses sourced <code>website</code> were published by the target on its '
                f'own pages. "Generated" = pattern-applied guess, not directly observed.</p>')
        sections.append(_html_section("people", "People OSINT (user enumeration)", len(people), body))

    # ---- Credential / breach exposure ----
    if breach:
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(b['name'])}</td><td>{esc(b.get('date'))}</td>"
            f"<td>{esc(b.get('pwned'))}</td><td>{esc(', '.join(b.get('data', [])[:6]))}</td></tr>"
            for d, bs in breach.items() for b in bs)
        n_breach = sum(len(v) for v in breach.values())
        body = (f'{_html_export_button("t-breach", "breach.csv")}'
                f'<table id="t-breach"><tr><th>Domain</th><th>Breach</th><th>Date</th>'
                f'<th>Accounts</th><th>Data classes</th></tr>{rows}</table>'
                f'<p class="note">Feeds password-spray candidate lists (T1110.003).</p>')
        sections.append(_html_section("breach", "Credential / breach exposure", n_breach, body))

    # ---- DNS zone transfer (AXFR) ----
    axfr = res.get("axfr") or {}
    allowed = {d: r for d, r in axfr.items() if (r or {}).get("transferred")}
    if any(_axfr_has_result(r) for r in axfr.values()):
        rows = ""
        for d, r in axfr.items():
            r = r or {}
            for ns_host, count in (r.get("transferred") or {}).items():
                rows += (f'<tr><td>{esc(d)}</td><td>{esc(ns_host)}</td>'
                         f'<td><strong class="bad">transfer ALLOWED</strong></td>'
                         f'<td>{count} record(s)</td></tr>')
            for ns_host, why in (r.get("refused") or {}).items():
                rows += (f'<tr><td>{esc(d)}</td><td>{esc(ns_host)}</td>'
                         f'<td><span class="good">refused</span></td>'
                         f'<td>{esc(why)}</td></tr>')
            for ns_host, err in (r.get("errors") or {}).items():
                rows += (f'<tr><td>{esc(d)}</td><td>{esc(ns_host)}</td>'
                         f'<td class="note">not conclusive</td>'
                         f'<td>{esc(err)} — unreachable, not a refusal</td></tr>')
        names = ""
        for d, r in allowed.items():
            shown = (r.get("records") or [])[:200]
            if shown:
                names += (f'<h4>{esc(d)} — disclosed names</h4><div style="overflow-x:auto">'
                          + ", ".join(f"<code>{esc(n)}</code>" for n in shown) + "</div>")
        body = (f'{_html_export_button("t-axfr", "zone_transfer.csv")}'
                f'<table id="t-axfr"><tr><th>Domain</th><th>Nameserver</th>'
                f'<th>Result</th><th>Detail</th></tr>{rows}</table>{names}'
                f'<p class="note">A nameserver answering AXFR hands over every record in '
                f'the zone in one query, including internal-only names no brute-force would '
                f'surface. Restrict transfers to authorised secondaries. An inconclusive '
                f'result is a reachability problem, not evidence that transfers are '
                f'refused.</p>')
        sections.append(_html_section("axfr", "DNS zone transfer (AXFR)",
                                      len(allowed), body))

    # ---- security.txt ----
    stxt = res.get("security_txt") or []
    if stxt:
        def _st_row(s):
            exp = ", ".join(s.get("expires") or []) or "—"
            exp_cell = (f'<strong class="bad">{esc(exp)} (expired)</strong>'
                        if s.get("expired") else esc(exp))
            def _links(key):
                vals = s.get(key) or []
                return ", ".join(f'<a href="{_h.escape(v)}" target="_blank" '
                                 f'rel="noopener">{esc(v)}</a>'
                                 if v.startswith("http") else esc(v) for v in vals) or "—"
            return (f'<tr><td>{esc(s["host"])}</td><td>{_links("contact")}</td>'
                    f'<td>{exp_cell}</td><td>{_links("policy")}</td></tr>')

        body = (f'{_html_export_button("t-stxt", "security_txt.csv")}'
                f'<div style="overflow-x:auto"><table id="t-stxt">'
                f'<tr><th>Host</th><th>Contact</th><th>Expires</th><th>Policy</th></tr>'
                + "".join(_st_row(s) for s in stxt) + '</table></div>'
                f'<p class="note">Names the disclosure channel a report should go to. The '
                f'Policy/Canonical/Acknowledgments URLs are worth following — they routinely '
                f'point at hosts nothing else surfaced. Per RFC 9116 an expired '
                f'<code>Expires</code> means the contact details should no longer be relied '
                f'on.</p>')
        sections.append(_html_section("securitytxt", "security.txt (RFC 9116)",
                                      len(stxt), body))

    # ---- TLS certificates ----
    certs = res.get("certs") or []
    if certs:
        def _cert_row(c):
            sans = c.get("sans") or []
            shown = ", ".join(f"<code>{esc(s)}</code>" for s in sans[:6]) or "—"
            if len(sans) > 6:
                shown += f' <span class="note">+{len(sans) - 6} more</span>'
            flags = _cert_flags(c)
            flag_cell = ("—" if not flags else
                         f'<strong class="bad">{esc(", ".join(flags))}</strong>')
            return (f'<tr><td>{esc(c["host"])}:{c["port"]}</td>'
                    f'<td>{esc(c.get("cn") or "—")}</td><td>{shown}</td>'
                    f'<td>{esc(c.get("issuer") or "—")}</td>'
                    f'<td>{esc((c.get("not_after") or "—")[:10])}</td>'
                    f'<td>{flag_cell}</td></tr>')

        rows = "".join(_cert_row(c) for c in _certs_by_risk(certs))
        cert_cols = ["Endpoint", "Subject CN", "SANs", "Issuer", "Expires", "Flags"]
        body = (f'{_html_export_button("t-certs", "tls_certificates.csv")}'
                f'{_html_filter_toolbar("t-certs")}'
                f'<div style="overflow-x:auto">'
                f'<table id="t-certs" data-filterable="1">'
                f'<tr>{"".join(f"<th>{c}</th>" for c in cert_cols)}</tr>'
                f'{_html_filter_row(cert_cols)}{rows}</table></div>'
                f'<p class="note">Read from the live handshake — the certificates '
                f'actually presented, including ones never submitted to a CT log. '
                f'In-scope SAN entries are added to the host list as <code>tls-san</code>; '
                f'other tenants\' names on a shared certificate are excluded.</p>')
        sections.append(_html_section("certs", "TLS certificates (as served)",
                                      len(certs), body))

    # ---- GitHub code exposure ----
    if gh:
        rows = "".join(
            f'<tr><td>{esc(it.get("repo"))}</td><td>{esc(it.get("path"))}</td>'
            f'<td><a href="{_h.escape(it.get("url") or "#")}">{esc(it.get("url"))}</a></td></tr>'
            for it in gh[:100])
        body = (f'{_html_export_button("t-github", "github_hits.csv")}'
                f'<table id="t-github"><tr><th>Repo</th><th>Path</th><th>URL</th></tr>{rows}</table>'
                f'<p class="note">Review each hit for leaked credentials, internal hostnames, or keys.</p>')
        sections.append(_html_section("github", "GitHub code exposure (T1593.003)", len(gh), body))

    # ---- Search-engine dork hits ----
    if dorks:
        rows = "".join(
            f'<tr><td>{esc(d["category"])}</td><td>{sev_badge(d["severity"])}</td>'
            f'<td>{esc(d["title"])}</td>'
            f'<td><a href="{_h.escape(d["link"])}">{esc(d["link"])}</a></td>'
            f'<td>{esc(d["snippet"])}</td></tr>'
            for d in dorks)
        body = (f'{_html_export_button("t-dorks", "dork_hits.csv")}'
                f'<table id="t-dorks"><tr><th>Category</th><th>Severity</th><th>Title</th>'
                f'<th>Link</th><th>Snippet</th></tr>{rows}</table>'
                f'<p class="note">Google-indexed pages matching admin/login/config/backup dork '
                f'patterns — verify each is actually reachable before reporting; a search-engine '
                f'hit can be stale.</p>')
        sections.append(_html_section("dorks", "Search-engine dork hits (T1593.002)", len(dorks), body))

    # ---- Cloud storage exposure ----
    if buckets:
        def _bucket_row(b):
            n_obj = b.get("object_count")
            n_int = len(b.get("interesting") or [])
            objs = f'{n_obj}{"+" if b.get("truncated") else ""}' if n_obj is not None else "—"
            pub = ('<strong class="bad">YES</strong>' if b["public"] else "no")
            sens = f'<strong class="bad">{n_int}</strong>' if n_int else "—"
            return (f'<tr><td><a href="{esc(b["url"])}" target="_blank" rel="noopener">'
                    f'{esc(b["name"])}</a></td>'
                    f'<td>{esc(b["provider"])}</td><td>{esc(b["status"])}</td>'
                    f'<td>{pub}</td><td>{objs}</td><td>{sens}</td>'
                    f'<td>{esc(human_bytes(b.get("bytes")) if b.get("bytes") else None)}</td></tr>')

        rows = "".join(_bucket_row(b) for b in sorted(buckets, key=lambda x: not x["public"]))
        body = (f'{_html_export_button("t-buckets", "buckets.csv")}'
                f'<div style="overflow-x:auto">'
                f'<table id="t-buckets"><tr><th>Bucket</th><th>Provider</th><th>Status</th>'
                f'<th>Public listing</th><th>Objects</th><th>Sensitive</th><th>Size</th></tr>'
                f'{rows}</table></div>')

        # Per-bucket object detail with direct links — sensitive-looking files
        # flagged and listed first.
        for b in [x for x in buckets if x.get("public") and x.get("objects")]:
            def _obj_row(o):
                flag = ' <span class="badge">sensitive</span>' if o.get("interesting") else ""
                return (f'<tr><td><a href="{esc(o["url"])}" target="_blank" rel="noopener">'
                        f'<code>{esc(o["key"])}</code></a>{flag}</td>'
                        f'<td>{esc(human_bytes(o.get("size")))}</td></tr>')
            ordered = ((b.get("interesting") or [])
                       + [o for o in b["objects"] if not o.get("interesting")])
            obj_rows = "".join(_obj_row(o) for o in ordered[:150])
            more = (f'<p class="note">Showing {min(len(ordered), 150)} of '
                    f'{b.get("object_count", len(ordered))} object(s)'
                    f'{" — listing truncated by the provider" if b.get("truncated") else ""}.</p>'
                    if len(ordered) > 150 or b.get("truncated") else "")
            body += (f'<h4>{esc(b["name"])} <span class="count">'
                     f'{b.get("object_count", 0)}</span></h4>'
                     f'<p class="note">Listing: <a href="{esc(b["url"])}" target="_blank" '
                     f'rel="noopener">{esc(b["url"])}</a></p>'
                     f'<div style="overflow-x:auto"><table><tr><th>Object</th><th>Size</th></tr>'
                     f'{obj_rows}</table></div>{more}')

        if any(b["public"] for b in buckets):
            body += ('<p class="note">Object links come from each bucket\'s own listing '
                     'response — lrecon does not download contents; fetch only what your '
                     'ROE permits.</p>')
        sections.append(_html_section("buckets", "Cloud storage exposure", len(buckets), body))

    # ---- Email security posture ----
    if email:
        body = ""
        for d, e in email.items():
            sp = e.get("spf_parsed") or {}
            dp = e.get("dmarc_parsed") or {}
            grade = e.get("grade") or "?"
            grade_cls = "bad" if grade == "FAIL" else ("warn" if grade == "WARN" else "good")

            def _rec(label, value):
                shown = (f'<code>{esc(value)}</code>' if value
                         else '<em>— not published</em>')
                return f'<tr><td>{label}</td><td style="word-break:break-all">{shown}</td></tr>'

            dkim_label = ("DKIM (<code>%s</code>)" % esc(e["dkim_selector"])
                          if e.get("dkim_selector") else "DKIM")
            recs = (_rec("SPF", e.get("spf")) + _rec("DMARC", e.get("dmarc"))
                    + _rec(dkim_label, e.get("dkim_record")))

            details = []
            if e.get("spf"):
                q = sp.get("all_qualifier")
                qual = {"-": "-all (hard fail)", "~": "~all (soft fail)",
                        "?": "?all (neutral)", "+": "+all (pass-any!)"}.get(q, "no all mechanism")
                lk_count, lk_caveat, lk_level = _spf_lookups(sp)
                lk_txt = esc(lk_count)
                if lk_level:
                    lk_txt = (f'<strong class="{lk_level}">{lk_txt} — '
                              f'{esc(lk_caveat)}</strong>')
                elif lk_caveat:
                    lk_txt = f'{lk_txt} <span class="note">({esc(lk_caveat)})</span>'
                inc = sp.get("includes") or []
                health = _spf_include_health(e)

                def _inc_html(target):
                    state = health.get((target or "").lower().rstrip("."))
                    label, bad = _SPF_INCLUDE_FLAGS.get(state, (None, False))
                    cell = f"<code>{esc(target)}</code>"
                    if not label:
                        return cell
                    cls = "bad" if bad else "note"
                    return f'{cell} <span class="{cls}">({esc(label)})</span>'

                inc_txt = (f"SPF includes ({len(inc)}): "
                           + ", ".join(_inc_html(i) for i in inc)
                           if inc else "SPF includes: none")
                details += [f"SPF policy: {esc(qual)}", f"SPF DNS lookups: {lk_txt}", inc_txt]
                if sp.get("redirect"):
                    details.append("SPF redirect: " + _inc_html(sp["redirect"]))
            if e.get("dmarc"):
                pol = f"<code>p={esc(dp.get('p') or '?')}</code>"
                for tag in ("sp", "pct", "adkim", "aspf"):
                    if dp.get(tag) is not None:
                        pol += f" <code>{tag}={esc(dp[tag])}</code>"
                details.append(f"DMARC policy: {pol}")
                details.append("DMARC rua: " + (", ".join(f"<code>{esc(u)}</code>"
                                                          for u in dp["rua"])
                                                if dp.get("rua") else "none"))
            if not e.get("dkim"):
                details.append("DKIM: not found on common selectors ("
                               + esc(", ".join(e.get("dkim_selectors_checked")
                                               or DKIM_SELECTORS))
                               + ") — inconclusive")
            # Reuse the Markdown wording, converting its ** emphasis to <strong>
            # so the two writers can't drift apart on what MTA-STS state means.
            details.append("MTA-STS: " + _md_emph_to_html(_mta_sts_text(e)))
            details.append("TLS-RPT: " + (f"<code>{esc(e['tls_rpt'])}</code>"
                                          if e.get("tls_rpt") else "not published"))
            details.append("DANE/TLSA: " + (f"present on {esc(', '.join(e['dane_mx']))}"
                                            if e.get("dane") else "not published"))
            mx_sugg = mx_banner_suggestion(mail_infra.get(d))
            if mx_sugg:
                details.append(f"<strong>Recommendation:</strong> {esc(mx_sugg)}")
            for kind, names in _email_services(e):
                details.append(f"Detected {esc(kind)}: "
                               + ", ".join(f"<strong>{esc(n)}</strong>" for n in names))
            issues = e.get("issues") or []
            body += (f'<h4>{esc(d)} <span class="{grade_cls}">{esc(grade)}</span></h4>'
                     f'<div style="overflow-x:auto"><table><tr><th>Mechanism</th>'
                     f'<th>Record</th></tr>{recs}</table></div>'
                     + ("<ul>" + "".join(f"<li>{x}</li>" for x in details) + "</ul>"
                        if details else "")
                     + "<p><strong>Issues:</strong></p><ul>"
                     + ("".join(f"<li>{esc(i)}</li>" for i in issues)
                        if issues else "<li>none</li>")
                     + "</ul>"
                     + ((f'<p><strong>Notes (advisory, grade-neutral):</strong></p><ul>'
                         + "".join(f"<li>{esc(n)}</li>" for n in (e.get("notes") or []))
                         + "</ul>") if e.get("notes") else "")
                     + (f'<p><strong>Phishing posture:</strong> '
                        f'{_md_emph_to_html((e.get("phishing_posture") or {})["summary"])}</p>'
                        if (e.get("phishing_posture") or {}).get("summary") else "")
                     + (f'<p class="note">DNS lookups failed '
                        f'({esc("; ".join(e["lookup_errors"]))}) — the affected mechanisms '
                        f'are <strong>inconclusive</strong>, not confirmed absent.</p>'
                        if e.get("lookup_errors") else ""))
        body += '<p class="note">SPF/DKIM/DMARC gaps enable email spoofing.</p>'
        sections.append(_html_section("email", "Email security posture", len(email), body))

    # ---- Favicon pivots ----
    if fp:
        fav_cols = ["Icon", "Hash", "IP", "Hostnames", "Org", "Cert CN", "Title", "Scope"]

        def _icon_cell(entry):
            img, src = entry.get("image"), ", ".join(entry.get("sources") or [])
            if not img:
                return "—"
            # title names the seed host the icon was served by, so the operator
            # can confirm it's the org's own logo.
            return (f'<img src="{esc(img)}" width="24" height="24" alt="favicon" '
                    f'title="served by {esc(src)}" style="vertical-align:middle">')

        rows = []
        skipped_lines = []
        for fh, entry in fp.items():
            icon = _icon_cell(entry)
            src = ", ".join(entry.get("sources") or []) or "seed domain"
            if entry.get("skipped"):
                skipped_lines.append(
                    f'<li>{icon} hash <code>{esc(fh)}</code> (served by {esc(src)}) — '
                    f'<strong>{entry["skipped"]:,} matches</strong>, too common to be a '
                    f'company marker; skipped</li>')
                continue
            for m in (entry.get("matches") or [])[:50]:
                names = ", ".join(m.get("hostnames") or []) or "—"
                scope = esc(m.get("scope", "?"))
                if m.get("in_cf"):
                    scope += ' <span class="note">· behind CF</span>'
                cls = "bad" if m.get("scope") == "cross-domain" else ""
                ipport = esc(m["ip"]) + (f":{esc(m['port'])}" if m.get("port") else "")
                rows.append(
                    f'<tr><td>{icon}</td><td><code>{esc(fh)}</code></td>'
                    f'<td><code>{ipport}</code></td>'
                    f'<td>{esc(names)}</td><td>{esc(m.get("org"))}</td>'
                    f'<td>{esc(m.get("cert_cn"))}</td><td>{esc((m.get("title") or "")[:60])}</td>'
                    f'<td class="{cls}">{scope}</td></tr>')
        body = ""
        if skipped_lines:
            body += f'<ul>{"".join(skipped_lines)}</ul>'
        if rows:
            body += (f'{_html_export_button("t-favicon", "favicon_pivots.csv")}'
                     f'{_html_filter_toolbar("t-favicon")}'
                     f'<div style="overflow-x:auto">'
                     f'<table id="t-favicon" data-filterable="1">'
                     f'<tr>{"".join(f"<th>{c}</th>" for c in fav_cols)}</tr>'
                     f'{_html_filter_row(fav_cols)}{"".join(rows)}</table></div>')
        body += ('<p class="note">A shared custom favicon is strong evidence of common '
                 'ownership, but only evidence — validate before reporting, and confirm SOW '
                 'coverage before touching any cross-domain host.</p>')
        sections.append(_html_section("favicon", "Favicon pivots", len(fp), body))

    # ---- nuclei findings ----
    if nuclei:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        nuclei_sorted = sorted(nuclei, key=lambda n: sev_order.get((n.get("severity") or "info"), 5))
        rows = "".join(
            f'<tr><td>{sev_badge(n.get("severity"))}</td><td>{esc(n.get("host"))}</td>'
            f'<td>{esc(n.get("name") or n.get("template"))}</td>'
            f'<td>{esc(", ".join(n["cve"]) if isinstance(n.get("cve"), list) else n.get("cve"))}</td></tr>'
            for n in nuclei_sorted)
        body = (f'{_html_export_button("t-nuclei", "nuclei_findings.csv")}'
                f'<table id="t-nuclei"><tr><th>Severity</th><th>Host</th><th>Template</th>'
                f'<th>CVE</th></tr>{rows}</table>')
        sections.append(_html_section("nuclei", "nuclei findings (templated vuln scan)", len(nuclei), body))

    # ---- Attack surface (primary table, always open) ----
    rows = []
    any_nonweb = False
    for h in hosts:
        if h.wildcard:
            continue
        cves = ", ".join(h.vulns[:5]) or "—"
        if non_web_ports(h.ports):
            any_nonweb = True
        rows.append(
            f"<tr><td>{esc(h.subdomain)}</td><td>{', '.join(h.ips) or '—'}</td>"
            f"<td>{esc(((h.asn or '') + ' ' + (h.org or '')).strip())[:40] or '—'}</td>"
            f"<td>{esc(host_countries(h))}</td>"
            f"<td>{_format_ports_html(h.ports)}</td>"
            f"<td>{esc(h.server or h.powered_by or None)}</td>"
            f"<td>{esc(getattr(h, 'waf', None))}</td>"
            f"<td>{(str(h.http_status) if h.http_status else '—')}</td>"
            f"<td>{esc(cves)}</td></tr>")
    as_cols = ["Subdomain", "IP(s)", "ASN/Org", "Country", "Open Ports", "Tech", "WAF/CDN",
               "HTTP", "CVEs"]
    body = (f'{_html_export_button("t-attacksurface", "attack_surface.csv")}'
            f'{_html_filter_toolbar("t-attacksurface")}'
            f'<table id="t-attacksurface" data-filterable="1">'
            f'<tr>{"".join(f"<th>{c}</th>" for c in as_cols)}</tr>'
            f'{_html_filter_row(as_cols)}'
            f'{"".join(rows)}</table>')
    if any_nonweb:
        body += ('<p class="note">Highlighted ports are non-web services (SSH, RDP, databases, '
                'etc.) — the HTTP probe never touches them, so they need a manual look.</p>')
    sections.append(_html_section("attacksurface", "Attack surface", len(rows), body, open_default=True))

    # ---- CVE hits ----
    if vulns:
        def _tech_confirmed_badge(h) -> str:
            if h.tech_confirmed is True:
                return '<span class="sev sev-low">TECH-CONFIRMED</span>'
            if h.tech_confirmed is False:
                return '<span class="sev sev-medium">UNCONFIRMED</span>'
            return "—"

        def _exploit_badge(h) -> str:
            kev_n, max_epss = _exploit_summary(h)
            parts = []
            if kev_n:
                parts.append(f'<span class="sev sev-critical">KEV×{kev_n}</span>')
            if max_epss is not None:
                parts.append(f'EPSS {round(max_epss * 100)}%')
            return " ".join(parts) or "—"

        rows = "".join(
            f'<tr><td>{esc(h.subdomain)}</td><td>{esc(", ".join(h.ips))}</td>'
            f'<td>{_tech_confirmed_badge(h)}</td><td>{_exploit_badge(h)}</td>'
            f'<td>{esc(", ".join(h.vulns))}</td></tr>' for h in vulns)
        engine = "Shodan" if any("shodan" in h.enrich_src for h in hosts) else "InternetDB"
        n_unconfirmed = sum(1 for h in vulns if h.tech_confirmed is False)
        note = (f'<p class="note">CVEs inferred from {esc(engine)} banner/version data. '
                f'Treat as leads, confirm with targeted validation.</p>')
        if n_unconfirmed:
            note += (f'<p class="note">{n_unconfirmed} host(s) marked UNCONFIRMED — the live '
                     f'tech-detect probe found no matching software for the reported CPE(s); '
                     f'the banner may be stale or the service since patched/replaced. Triage '
                     f'TECH-CONFIRMED hosts first.</p>')
        body = (f'{_html_export_button("t-cve", "cve_hits.csv")}'
                f'<table id="t-cve"><tr><th>Subdomain</th><th>IP(s)</th><th>Tech-stack</th>'
                f'<th>Exploitability</th><th>CVEs</th></tr>{rows}</table>{note}')
        sections.append(_html_section("cve", "CVE hits (validate before reporting)", len(vulns), body))

    # ---- Screenshot evidence (embedded, self-contained) ----
    if shots_dir:
        import base64
        shots = []
        for h in hosts:
            if h.wildcard or not h.http_status:
                continue
            safe = _live_url(h).replace("https://", "").replace("http://", "").replace("/", "_")[:80]
            png = Path(shots_dir) / f"{safe}.png"
            try:
                if not png.is_file():
                    continue
                data = png.read_bytes()
            except OSError:
                continue
            if not data or len(data) > SCREENSHOT_MAX_BYTES:
                # Over the cap: link the sidecar file rather than bloating the HTML.
                continue
            b64 = base64.b64encode(data).decode("ascii")
            shots.append(
                f'<figure class="shot"><img loading="lazy" alt="{esc(h.subdomain)}" '
                f'src="data:image/png;base64,{b64}">'
                f'<figcaption>{esc(h.subdomain)}</figcaption></figure>')
        if shots:
            body = (f'<div class="shots">{"".join(shots)}</div>'
                    f'<p class="note">Live-page captures embedded as evidence (over '
                    f'{SCREENSHOT_MAX_BYTES // 1024} KB each are left in the sidecar '
                    f'<code>_shots/</code> directory instead).</p>')
            sections.append(_html_section("shots", "Screenshots", len(shots), body))

    # ---- Handoff command pack ----
    packs = handoff_commands(hosts)
    if packs:
        blocks = "".join(
            f'<h4>{esc(h.subdomain)} <span class="count">risk {getattr(h, "risk_score", 0)}</span></h4>'
            f'<pre class="handoff">{esc(chr(10).join(cmds))}</pre>'
            for h, cmds in packs)
        body = (f'{blocks}'
                f'<p class="note">Ready-to-run follow-up commands, ordered by risk. Every '
                f'command is active and touches the target — review and run only within your '
                f'ROE. Also written to <code>&lt;base&gt;.handoff.sh</code>.</p>')
        sections.append(_html_section("handoff", "Handoff command pack", len(packs), body))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>lrecon — {esc(', '.join(domains))}</title>
<style>
:root {{ color-scheme: light; }}
body {{ font: 14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; margin: 0;
       color: #1a1a1a; background: #fff; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: .5rem; }}
.meta {{ color: #555; margin-top: -.5rem; }}
.toolbar {{ margin: 1rem 0; display: flex; gap: .5rem; flex-wrap: wrap; }}
.toolbar button {{ font: inherit; padding: .35rem .8rem; border: 1px solid #999; border-radius: 4px;
                   background: #f4f4f4; cursor: pointer; }}
.toolbar button:hover {{ background: #e8e8e8; }}
.stats {{ display: flex; gap: .75rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
.stat {{ border: 1px solid #ddd; border-radius: 6px; padding: .6rem 1rem; min-width: 8rem; }}
.stat .n {{ font-size: 1.4rem; font-weight: 700; display: block; }}
.stat .l {{ font-size: .78rem; color: #666; text-transform: uppercase; letter-spacing: .03em; }}
details.section {{ border: 1px solid #ddd; border-radius: 6px; margin-bottom: .6rem; overflow: hidden; }}
details.section summary {{ cursor: pointer; padding: .6rem .9rem; font-weight: 600; font-size: 15px;
                           color: #b31b1b; background: #faf5f5; list-style: revert; }}
details.section summary:hover {{ background: #f5eaea; }}
details.section .count {{ color: #666; font-weight: 400; font-size: .85em; }}
.section-body {{ padding: .8rem 1rem 1rem; }}
.export-btn {{ font: inherit; font-size: .8rem; padding: .3rem .7rem; margin-bottom: .5rem;
              border: 1px solid #999; border-radius: 4px; background: #fff; cursor: pointer; }}
.export-btn:hover {{ background: #f0f0f0; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ border: 1px solid #ddd; padding: 4px 8px; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; position: sticky; top: 0; }}
code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }}
tr:nth-child(even) {{ background: #fafafa; }}
.filterbar {{ display: flex; align-items: center; gap: .6rem; margin-bottom: .5rem; }}
.filtercount {{ font-size: .8rem; color: #666; }}
/* Sits above the boxes it describes — the old note was below the table, which
   is not where anyone looks before typing into a filter at the top. */
.filterhint {{ font-size: .78rem; line-height: 1.5; color: #555; background: #f7f7f7;
              border: 1px solid #e0e0e0; border-radius: 4px; padding: .4rem .6rem;
              margin-bottom: .5rem; }}
.filterhint code {{ font-size: .95em; }}
/* Sits directly under the sticky header so the inputs stay reachable while
   scrolling a long table. 1.9rem is the header's own height. */
th.filter-th {{ position: sticky; top: 1.9rem; background: #f4f4f4; padding: 2px 4px; }}
.filter-input {{ font: inherit; font-size: 12px; width: 100%; box-sizing: border-box;
                padding: 2px 4px; border: 1px solid #ccc; border-radius: 3px;
                background: #fff; color: inherit; font-weight: 400; }}
.filter-input:focus {{ outline: 2px solid #b31b1b; outline-offset: -1px; }}
tr.filter-row {{ background: #f4f4f4 !important; }}
.note {{ color: #555; font-style: italic; }}
.sev {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px;
       font-weight: 700; letter-spacing: .02em; }}
.sev-critical {{ background: #7a0d0d; color: #fff; }}
.sev-high {{ background: #c0392b; color: #fff; }}
.sev-medium {{ background: #e67e22; color: #fff; }}
.sev-low {{ background: #95a5a6; color: #fff; }}
.sev-info {{ background: #bdc3c7; color: #333; }}
.portflag {{ background: #e67e22; color: #fff; padding: 0 5px; border-radius: 3px;
            font-weight: 600; cursor: help; }}
.bad {{ color: #c0392b; }}
.warn {{ color: #e67e22; }}
.good {{ color: #1e8449; }}
h4 {{ margin: 1.1rem 0 .4rem; font-size: 14px; }}
.badge {{ display: inline-block; background: #c0392b; color: #fff; padding: 0 5px;
         border-radius: 3px; font-size: 10px; font-weight: 700; margin-left: .3rem;
         text-transform: uppercase; letter-spacing: .02em; }}
.shots {{ display: flex; flex-wrap: wrap; gap: .8rem; }}
.shot {{ margin: 0; border: 1px solid #ddd; border-radius: 6px; overflow: hidden;
        width: 240px; background: #fafafa; }}
.shot img {{ display: block; width: 100%; height: auto; }}
.shot figcaption {{ font-size: 12px; padding: .35rem .5rem; word-break: break-all; }}
pre.handoff {{ background: #f0f0f0; padding: .6rem .8rem; border-radius: 4px; overflow-x: auto;
              font-size: 12px; line-height: 1.5; margin: .2rem 0 .8rem; }}
@media (prefers-color-scheme: dark) {{
  :root {{ color-scheme: dark; }}
  body {{ background: #16181c; color: #e6e6e6; }}
  h1 {{ border-color: #444; }}
  .meta {{ color: #aaa; }}
  .toolbar button {{ background: #24272d; border-color: #555; color: #e6e6e6; }}
  .toolbar button:hover {{ background: #2c2f36; }}
  .stat {{ border-color: #3a3d44; }}
  .stat .l {{ color: #999; }}
  details.section {{ border-color: #3a3d44; }}
  details.section summary {{ background: #241a1a; color: #ff8a80; }}
  details.section summary:hover {{ background: #2b1f1f; }}
  .export-btn {{ background: #24272d; border-color: #555; color: #e6e6e6; }}
  .export-btn:hover {{ background: #2c2f36; }}
  th {{ background: #23262c; }}
  th, td {{ border-color: #3a3d44; }}
  code {{ background: #2a2d33; }}
  tr:nth-child(even) {{ background: #1c1f24; }}
  .filtercount {{ color: #999; }}
  .filterhint {{ background: #1c1f24; border-color: #3a3d44; color: #aaa; }}
  th.filter-th {{ background: #23262c; }}
  tr.filter-row {{ background: #23262c !important; }}
  .filter-input {{ background: #16181c; border-color: #555; color: #e6e6e6; }}
  .filter-input:focus {{ outline-color: #ff8a80; }}
  .note {{ color: #aaa; }}
  .bad {{ color: #ff8a80; }}
  .warn {{ color: #ffb74d; }}
  .good {{ color: #81c784; }}
  .shot {{ border-color: #3a3d44; background: #1c1f24; }}
  pre.handoff {{ background: #1c1f24; }}
}}
@media print {{
  .toolbar {{ display: none; }}
  details.section {{ break-inside: avoid; }}
}}
</style></head><body><div class="wrap">
<h1>External Recon — {esc(', '.join(domains))}</h1>
<p class="meta">Authorized engagement · Generated {ts} · ATT&amp;CK TA0043 Reconnaissance</p>
<div class="stats">
<div class="stat"><span class="n">{len(hosts)}</span><span class="l">Subdomains</span></div>
<div class="stat"><span class="n">{n_live}</span><span class="l">Live</span></div>
<div class="stat"><span class="n">{len(entry_points)}</span><span class="l">Entry points</span></div>
<div class="stat"><span class="n">{len(takeovers)}</span><span class="l">Takeover leads</span></div>
<div class="stat"><span class="n">{len(vulns)}</span><span class="l">Hosts w/ CVEs</span></div>
<div class="stat"><span class="n">{len(people)}</span><span class="l">People (OSINT)</span></div>
</div>
<div class="toolbar">
<button type="button" onclick="toggleAllSections(true)">Expand all</button>
<button type="button" onclick="toggleAllSections(false)">Collapse all</button>
</div>
{"".join(sections)}
<p class="note">Full per-target CSV/JSON exports also written alongside this report
(<code>.targets.csv</code>, <code>.users.csv</code>, <code>.json</code>) — the buttons above export
exactly what's rendered on this page, which may be truncated for display.</p>
</div>
<script>
function exportTableToCSV(tableId, filename) {{
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = Array.prototype.slice.call(table.querySelectorAll('tr'))
    // The filter row is UI, not data, and a hidden row is one the operator
    // has deliberately excluded — exporting either produces a file that
    // doesn't match what is on screen.
    .filter(function(row) {{
      return !row.classList.contains('filter-row') && row.style.display !== 'none';
    }});
  var csv = rows.map(function(row) {{
    var cells = Array.prototype.slice.call(row.querySelectorAll('th,td'));
    return cells.map(function(cell) {{
      return '"' + cell.textContent.trim().replace(/"/g, '""') + '"';
    }}).join(',');
  }}).join('\\r\\n');
  var blob = new Blob([csv], {{type: 'text/csv;charset=utf-8;'}});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}
function toggleAllSections(open) {{
  document.querySelectorAll('details.section').forEach(function(d) {{ d.open = open; }});
}}
// Live column filters. Substring, case-insensitive, all columns ANDed; a
// leading '!' negates so rows can be excluded as well as selected.
// A box holds one or more comma-separated values, OR'd together — ports and
// HTTP codes are exactly the columns you want to ask "443 or 8443" about, and a
// single substring could not express that. A leading '!' negates the whole set,
// so !403,404 hides both. Empty parts are dropped so a trailing comma typed
// mid-thought doesn't blank the table.
function _filterTerm(raw) {{
  var v = raw.trim().toLowerCase();
  if (!v) return null;
  var negate = v.charAt(0) === '!';
  if (negate) v = v.slice(1).trim();
  var parts = v.split(',').map(function(p) {{ return p.trim(); }})
               .filter(function(p) {{ return p.length > 0; }});
  return parts.length ? {{negate: negate, parts: parts}} : null;
}}
// Plain substring, for every column including the numeric ones. Filtering here
// is exploratory — you type a fragment and narrow as you go — so typing 20 has
// to surface 20, 2070 and 8020 alike. Numbers were briefly matched as whole
// values to stop 443 pulling in 8443, but that trades away the far more common
// case: you rarely know the exact port up front, which is why you are filtering.
function _matches(cell, part) {{
  return cell.indexOf(part) !== -1;
}}
function applyFilters(table) {{
  var inputs = Array.prototype.slice.call(table.querySelectorAll('.filter-input'));
  var terms = inputs.map(function(i) {{ return _filterTerm(i.value); }});
  var body = Array.prototype.slice.call(table.querySelectorAll('tr')).filter(function(r) {{
    return !r.classList.contains('filter-row') && !r.querySelector('th');
  }});
  var shown = 0;
  body.forEach(function(row) {{
    var cells = row.querySelectorAll('td');
    var keep = terms.every(function(term, i) {{
      if (!term || !cells[i]) return true;
      var cell = cells[i].textContent.toLowerCase();
      var hit = term.parts.some(function(p) {{ return _matches(cell, p); }});
      return term.negate ? !hit : hit;
    }});
    row.style.display = keep ? '' : 'none';
    if (keep) shown++;
  }});
  var counter = document.querySelector('.filtercount[data-for="' + table.id + '"]');
  if (counter) {{
    counter.textContent = shown === body.length
      ? ('showing all ' + body.length + ' row(s)')
      : ('showing ' + shown + ' of ' + body.length + ' row(s) — filtered');
  }}
}}
function resetFilters(tableId) {{
  var table = document.getElementById(tableId);
  if (!table) return;
  table.querySelectorAll('.filter-input').forEach(function(i) {{ i.value = ''; }});
  applyFilters(table);
}}
document.addEventListener('DOMContentLoaded', function() {{
  document.querySelectorAll('table[data-filterable]').forEach(function(table) {{
    table.querySelectorAll('.filter-input').forEach(function(input) {{
      input.addEventListener('input', function() {{ applyFilters(table); }});
    }});
    applyFilters(table);
  }});
}});
</script>
</body></html>"""
    Path(path).write_text(doc)


async def screenshot_hosts(urls, out_dir) -> int:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        log("[!] screenshots: playwright not installed — "
            "`pip install playwright && playwright install chromium`")
        return 0
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    n = 0
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        for url in urls:
            try:
                page = await browser.new_page()
                await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                safe = url.replace("https://", "").replace("http://", "").replace("/", "_")[:80]
                await page.screenshot(path=str(Path(out_dir) / f"{safe}.png"))
                await page.close()
                n += 1
            except Exception:
                pass
        await browser.close()
    return n


