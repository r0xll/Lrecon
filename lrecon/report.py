from __future__ import annotations
import asyncio, csv, json
from datetime import datetime, timezone
from pathlib import Path
from .common import *

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def write_csv(hosts, path) -> int:
    """
    Flat target list for client scope confirmation — one row per discovered
    host (including wildcard-suspect ones, so the client can weigh in on
    those too). Deliberately just subdomain + IPs (+ per-IP ASN): this is
    "here's what we found in your scope, please confirm ownership," not a
    vuln report. The asn column is positionally parallel to ips — the ASN
    at index i belongs to the IP at index i, blank where unresolved (e.g.
    no IPinfo token configured for that run). For single-IP hosts, falls
    back to the scalar h.asn if ip_asn wasn't populated for that IP —
    unambiguous with only one IP, and guards against any future caller of
    apply_ipinfo() that omits the optional ip argument.
    """
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["subdomain", "ips", "asn"])
        for h in hosts:
            if len(h.ips) == 1:
                asn_col = h.ip_asn.get(h.ips[0]) or h.asn or ""
            else:
                asn_col = ", ".join(h.ip_asn.get(ip, "") for ip in h.ips)
            w.writerow([h.subdomain, ", ".join(h.ips), asn_col])
    return len(hosts)


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


def write_markdown(hosts, domains, res, path) -> None:
    per_source = res.get("per_source", {})
    cf = res.get("cf", {})
    entry_points = res.get("entry_points") or []
    live = [h for h in hosts if h.ips or h.http_status]
    vulns = [h for h in hosts if h.vulns]
    takeovers = [h for h in hosts if h.takeover]
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

    if per_source:
        lines += ["## Passive source contribution", "",
                  "| Source | In-scope hosts found |", "|---|---|"]
        for s in sorted(per_source, key=lambda k: -per_source[k]):
            lines.append(f"| {s} | {per_source[s]} |")
        lines.append("")

    whois = res.get("whois") or {}
    if whois:
        lines += ["## Domain registration (WHOIS/RDAP)", "",
                  "| Domain | Registrar | Created | Expires | Status | Nameservers |",
                  "|---|---|---|---|---|---|"]
        for d, w in whois.items():
            status = ", ".join(w.get("status", [])[:3]) or "—"
            ns = ", ".join(w.get("nameservers", [])[:4]) or "—"
            lines.append(f"| {d} | {w.get('registrar') or '—'} | {w.get('created') or '—'} "
                         f"| {w.get('expires') or '—'} | {status} | {ns} |")
        lines.append("")

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
        for h in takeovers:
            lines.append(f"- **{h.subdomain}** — {h.takeover}")
        lines += ["", "> Validate by attempting to claim the dangling resource in a "
                  "controlled manner per ROE before reporting as confirmed.", ""]

    if cf and cf.get("detected"):
        conf = {ip: v for ip, v in cf["candidates"].items() if v["confirmed"]}
        unconf = {ip: v for ip, v in cf["candidates"].items() if not v["confirmed"]}
        lines += ["## Cloudflare origin exposure — WAF/DDoS bypass",
                  "",
                  f"Cloudflare fronts {len(cf['fronted'])} in-scope host(s). "
                  f"Origin IPs reachable outside Cloudflare let an attacker bypass "
                  f"the WAF/DDoS layer entirely (origin IP disclosure).", ""]
        if conf:
            lines += ["**Confirmed origin candidates** (responded to spoofed Host header):", ""]
            for ip, v in conf.items():
                lines.append(f"- `{ip}` — {v['evidence']} — sources: {', '.join(v['sources'])}")
            lines += ["",
                      "> Finding: Origin IP disclosure enabling WAF bypass. "
                      "CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) baseline — "
                      "raise if the origin exposes services CF was masking. "
                      "Remediation: restrict origin firewall to accept only Cloudflare IP "
                      "ranges (or use Authenticated Origin Pulls / cloudflared tunnel).", ""]
        if unconf:
            lines += ["**Unconfirmed candidate IPs** (found passively, not verified):", ""]
            for ip, v in unconf.items():
                lines.append(f"- `{ip}` — sources: {', '.join(v['sources'])}")
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
                  "| Bucket | Provider | Status | Public listing |", "|---|---|---|---|"]
        for b in sorted(buckets, key=lambda x: not x["public"]):
            lines.append(f"| {b['name']} | {b['provider']} | {b['status']} | "
                         f"{'YES' if b['public'] else 'no'} |")
        if any(b["public"] for b in buckets):
            lines += ["", "> Public-listable buckets are a data-exposure finding — "
                      "enumerate contents (read-only) to assess sensitivity per ROE.", ""]
        else:
            lines.append("")

    email = res.get("email") or {}
    if email:
        lines += ["## Email security posture", "",
                  "| Domain | Grade | Issues |", "|---|---|---|"]
        for d, e in email.items():
            issues = "; ".join(e.get("issues", [])) or "none"
            lines.append(f"| {d} | {e.get('grade','?')} | {issues} |")
        lines += ["", "> SPF/DKIM/DMARC gaps enable email spoofing and strengthen "
                  "phishing pretext (relevant if the SOW covers social engineering).", ""]

    fp = res.get("favicon_pivots") or {}
    if fp:
        lines += ["## Favicon pivots (shadow assets sharing favicon)", ""]
        for fh, ips in fp.items():
            lines.append(f"- hash `{fh}` -> {', '.join(ips[:20])}")
        lines += ["", "> IPs serving the same favicon outside the known surface are "
                  "candidate shadow/origin hosts — validate ownership before reporting.", ""]

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
              "| Subdomain | IP(s) | ASN / Org | Open Ports | Tech | HTTP | CVEs |",
              "|---|---|---|---|---|---|---|"]
    for h in hosts:
        if h.wildcard:
            continue
        ips = ", ".join(h.ips) or "—"
        asn_org = " ".join(x for x in (h.asn, (h.org or "")[:20]) if x) or "—"
        ports = ", ".join(map(str, h.ports)) or "—"
        tech = h.server or h.powered_by or (h.cpes[0] if h.cpes else "—")
        http = f"{h.scheme} {h.http_status}" if h.http_status else "—"
        v = ", ".join(h.vulns[:5]) + ("…" if len(h.vulns) > 5 else "") if h.vulns else "—"
        lines.append(f"| {h.subdomain} | {ips} | {asn_org} | {ports} | {tech} | {http} | {v} |")

    if vulns:
        lines += ["", "## CVE hits (validate before reporting)", ""]
        for h in vulns:
            lines.append(f"- **{h.subdomain}** ({', '.join(h.ips)}): {', '.join(h.vulns)}")
        engine = "Shodan" if any("shodan" in h.enrich_src for h in hosts) else "InternetDB"
        lines += ["", f"> CVEs inferred from {engine} banner/version data. "
                  "Treat as leads, confirm with targeted validation."]

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


def _html_export_button(table_id: str, filename: str) -> str:
    return (f'<button class="export-btn" type="button" '
            f'onclick="exportTableToCSV(\'{table_id}\',\'{filename}\')">Export CSV</button>')


def write_html(hosts, domains, res, path) -> None:
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

    takeovers = [h for h in hosts if h.takeover]
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

    # ---- Passive source contribution ----
    if per_source:
        rows = "".join(f"<tr><td>{esc(s)}</td><td>{per_source[s]}</td></tr>"
                       for s in sorted(per_source, key=lambda k: -per_source[k]))
        body = (f'<table id="t-sources"><tr><th>Source</th><th>In-scope hosts found</th></tr>{rows}</table>')
        sections.append(_html_section("sources", "Passive source contribution", len(per_source), body))

    # ---- Domain registration (WHOIS/RDAP) ----
    if whois:
        rows = "".join(
            f"<tr><td>{esc(d)}</td><td>{esc(w.get('registrar'))}</td><td>{esc(w.get('created'))}</td>"
            f"<td>{esc(w.get('expires'))}</td><td>{esc(', '.join(w.get('status', [])[:3]))}</td>"
            f"<td>{esc(', '.join(w.get('nameservers', [])[:4]))}</td></tr>"
            for d, w in whois.items())
        body = (f'{_html_export_button("t-whois", "whois.csv")}'
                f'<table id="t-whois"><tr><th>Domain</th><th>Registrar</th><th>Created</th>'
                f'<th>Expires</th><th>Status</th><th>Nameservers</th></tr>{rows}</table>')
        sections.append(_html_section("whois", "Domain registration (WHOIS/RDAP)", len(whois), body))

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
        rows = "".join(f"<tr><td>{esc(h.subdomain)}</td><td>{esc(h.takeover)}</td></tr>"
                       for h in takeovers)
        body = (f'{_html_export_button("t-takeover", "takeover_leads.csv")}'
                f'<table id="t-takeover"><tr><th>Subdomain</th><th>Detail</th></tr>{rows}</table>'
                f'<p class="note">Validate by attempting to claim the dangling resource in a '
                f'controlled manner per ROE before reporting as confirmed.</p>')
        sections.append(_html_section("takeover", "Subdomain takeover leads (T1584.001)",
                                      len(takeovers), body))

    # ---- Cloudflare origin exposure ----
    if cf.get("detected"):
        conf = {ip: v for ip, v in cf["candidates"].items() if v["confirmed"]}
        unconf = {ip: v for ip, v in cf["candidates"].items() if not v["confirmed"]}
        body = (f'<p>Cloudflare fronts {len(cf["fronted"])} in-scope host(s). Origin IPs reachable '
                f'outside Cloudflare let an attacker bypass the WAF/DDoS layer entirely.</p>')
        if conf:
            rows = "".join(f'<tr><td><code>{esc(ip)}</code></td><td>{esc(v["evidence"])}</td>'
                          f'<td>{esc(", ".join(v["sources"]))}</td></tr>' for ip, v in conf.items())
            body += (f'<p><b>Confirmed origin candidates</b> (responded to spoofed Host header):</p>'
                     f'<table id="t-cforigin"><tr><th>IP</th><th>Evidence</th><th>Sources</th></tr>{rows}</table>')
        if unconf:
            rows = "".join(f'<tr><td><code>{esc(ip)}</code></td><td>{esc(", ".join(v["sources"]))}</td></tr>'
                          for ip, v in unconf.items())
            body += (f'<p><b>Unconfirmed candidate IPs</b> (found passively, not verified):</p>'
                     f'<table><tr><th>IP</th><th>Sources</th></tr>{rows}</table>')
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
        rows = "".join(
            f"<tr><td>{esc(p.email)}</td><td>{esc(p.name)}</td><td>{esc(p.position)}</td>"
            f"<td>{esc(p.confidence)}</td><td>{'yes' if p.generated else ''}</td>"
            f"<td>{esc(p.smtp_status)}</td><td>{esc(', '.join(sorted(p.source)))}</td></tr>"
            for p in people)
        body = (f'{_html_export_button("t-people", "users.csv")}'
                f'<table id="t-people"><tr><th>Email</th><th>Name</th><th>Position</th>'
                f'<th>Confidence</th><th>Generated</th><th>SMTP status</th><th>Source</th></tr>'
                f'{rows}</table>'
                f'<p class="note">Company-affiliated OSINT, not personal accounts. '
                f'"Generated" = pattern-applied guess, not directly observed.</p>')
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
        rows = "".join(
            f'<tr><td>{esc(b["name"])}</td><td>{esc(b["provider"])}</td><td>{esc(b["status"])}</td>'
            f'<td>{"YES" if b["public"] else "no"}</td></tr>'
            for b in sorted(buckets, key=lambda x: not x["public"]))
        body = (f'{_html_export_button("t-buckets", "buckets.csv")}'
                f'<table id="t-buckets"><tr><th>Bucket</th><th>Provider</th><th>Status</th>'
                f'<th>Public listing</th></tr>{rows}</table>')
        sections.append(_html_section("buckets", "Cloud storage exposure", len(buckets), body))

    # ---- Email security posture ----
    if email:
        rows = "".join(
            f'<tr><td>{esc(d)}</td><td>{esc(e.get("grade"))}</td>'
            f'<td>{esc("; ".join(e.get("issues", [])) or "none")}</td></tr>'
            for d, e in email.items())
        body = (f'<table id="t-email"><tr><th>Domain</th><th>Grade</th><th>Issues</th></tr>{rows}</table>'
                f'<p class="note">SPF/DKIM/DMARC gaps enable email spoofing.</p>')
        sections.append(_html_section("email", "Email security posture", len(email), body))

    # ---- Favicon pivots ----
    if fp:
        rows = "".join(f'<li>hash <code>{esc(fh)}</code> -&gt; {esc(", ".join(ips[:20]))}</li>'
                       for fh, ips in fp.items())
        body = f'<ul>{rows}</ul><p class="note">Validate ownership before reporting as shadow assets.</p>'
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
    for h in hosts:
        if h.wildcard:
            continue
        cves = ", ".join(h.vulns[:5]) or "—"
        rows.append(
            f"<tr><td>{esc(h.subdomain)}</td><td>{', '.join(h.ips) or '—'}</td>"
            f"<td>{esc(((h.asn or '') + ' ' + (h.org or '')).strip())[:40] or '—'}</td>"
            f"<td>{', '.join(map(str, h.ports)) or '—'}</td>"
            f"<td>{esc(h.server or h.powered_by or None)}</td>"
            f"<td>{(str(h.http_status) if h.http_status else '—')}</td>"
            f"<td>{esc(cves)}</td></tr>")
    body = (f'{_html_export_button("t-attacksurface", "attack_surface.csv")}'
            f'<table id="t-attacksurface"><tr><th>Subdomain</th><th>IP(s)</th><th>ASN/Org</th>'
            f'<th>Open Ports</th><th>Tech</th><th>HTTP</th><th>CVEs</th></tr>{"".join(rows)}</table>')
    sections.append(_html_section("attacksurface", "Attack surface", len(rows), body, open_default=True))

    # ---- CVE hits ----
    if vulns:
        rows = "".join(
            f'<tr><td>{esc(h.subdomain)}</td><td>{esc(", ".join(h.ips))}</td>'
            f'<td>{esc(", ".join(h.vulns))}</td></tr>' for h in vulns)
        engine = "Shodan" if any("shodan" in h.enrich_src for h in hosts) else "InternetDB"
        body = (f'{_html_export_button("t-cve", "cve_hits.csv")}'
                f'<table id="t-cve"><tr><th>Subdomain</th><th>IP(s)</th><th>CVEs</th></tr>{rows}</table>'
                f'<p class="note">CVEs inferred from {esc(engine)} banner/version data. '
                f'Treat as leads, confirm with targeted validation.</p>')
        sections.append(_html_section("cve", "CVE hits (validate before reporting)", len(vulns), body))

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
.note {{ color: #555; font-style: italic; }}
.sev {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px;
       font-weight: 700; letter-spacing: .02em; }}
.sev-critical {{ background: #7a0d0d; color: #fff; }}
.sev-high {{ background: #c0392b; color: #fff; }}
.sev-medium {{ background: #e67e22; color: #fff; }}
.sev-low {{ background: #95a5a6; color: #fff; }}
.sev-info {{ background: #bdc3c7; color: #333; }}
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
  .note {{ color: #aaa; }}
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
  var rows = Array.prototype.slice.call(table.querySelectorAll('tr'));
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


