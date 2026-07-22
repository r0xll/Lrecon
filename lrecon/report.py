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
def write_html(hosts, domains, res, path) -> None:
    import html as _h
    cf = res.get("cf", {})
    entry_points = res.get("entry_points") or []
    rows = []
    for h in hosts:
        if h.wildcard:
            continue
        cves = ", ".join(h.vulns[:5]) or "—"
        rows.append(
            f"<tr><td>{_h.escape(h.subdomain)}</td><td>{', '.join(h.ips) or '—'}</td>"
            f"<td>{_h.escape((h.asn or '') + ' ' + (h.org or ''))[:40] or '—'}</td>"
            f"<td>{', '.join(map(str, h.ports)) or '—'}</td>"
            f"<td>{_h.escape(h.server or h.powered_by or '—')}</td>"
            f"<td>{(str(h.http_status) if h.http_status else '—')}</td>"
            f"<td>{_h.escape(cves)}</td></tr>")
    takeovers = [h for h in hosts if h.takeover]
    to_html = "".join(f"<li><b>{_h.escape(h.subdomain)}</b> — {_h.escape(h.takeover)}</li>"
                      for h in takeovers)
    cf_html = ""
    if cf.get("detected"):
        conf = [f"<li><code>{ip}</code> — {_h.escape(v['evidence'] or '')}</li>"
                for ip, v in cf["candidates"].items() if v["confirmed"]]
        cf_html = (f"<h2>Cloudflare origin exposure</h2><p>Fronts {len(cf['fronted'])} host(s). "
                   f"Confirmed origin candidates:</p><ul>{''.join(conf) or '<li>none confirmed</li>'}</ul>")
    ep_html = "<p>No high-confidence entry points identified from this pass.</p>"
    if entry_points:
        ep_rows = "".join(
            f"<tr><td>{_h.escape(e['severity'].upper())}</td><td>{_h.escape(str(e['target']))}</td>"
            f"<td>{_h.escape(e['summary'])}</td><td>{_h.escape(e.get('attck') or '—')}</td></tr>"
            for e in entry_points)
        ep_html = (f"<table><tr><th>Severity</th><th>Target</th><th>Finding</th>"
                   f"<th>ATT&amp;CK</th></tr>{ep_rows}</table>"
                   f"<p><i>Leads, not confirmed compromises — validate per ROE.</i></p>")
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>lrecon — {_h.escape(', '.join(domains))}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;max-width:1100px}}
h1{{border-bottom:2px solid #333}} h2{{margin-top:2rem;color:#b31b1b}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:4px 8px;text-align:left}}
th{{background:#f4f4f4}} code{{background:#f0f0f0;padding:1px 4px}}
tr:nth-child(even){{background:#fafafa}}</style></head><body>
<h1>External Recon — {_h.escape(', '.join(domains))}</h1>
<p>Authorized engagement. Hosts: {len(hosts)} · Live: {sum(1 for h in hosts if h.http_status)} ·
Takeover leads: {len(takeovers)} · Potential entry points: {len(entry_points)}</p>
<h2>⚠ Potential entry points</h2>
{ep_html}
{('<h2>Subdomain takeover leads</h2><ul>'+to_html+'</ul>') if takeovers else ''}
{cf_html}
<h2>Attack surface</h2><table><tr><th>Subdomain</th><th>IP(s)</th><th>ASN/Org</th>
<th>Ports</th><th>Tech</th><th>HTTP</th><th>CVEs</th></tr>{''.join(rows)}</table>
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


