from __future__ import annotations
import asyncio, html, ipaddress, json, re
import httpx
from .common import *
from .sources import cname_target_status, get_resolver, resolve_full
from .enrich import enrich_ipinfo
from .tlsinfo import cert_matches_scope, fetch_cert, in_scope_cert_names

# --------------------------------------------------------------------------- #
# Cloudflare origin discovery (origin IP disclosure -> WAF bypass)
# --------------------------------------------------------------------------- #
async def load_cf_ranges(client) -> list:
    nets = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        try:
            r = await client.get(url, timeout=15)
            if r.status_code == 200:
                for line in r.text.split():
                    try:
                        nets.append(ipaddress.ip_network(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
    if not nets:
        nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    return nets


def in_cf(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except Exception:
        return False


async def cloudflare_origin_analysis(client, probe_client, domains, hosts, keys, cf_nets,
                                     active, resolver_ns) -> dict:
    """
    Passive candidate collection + optional active confirmation.
    Candidate sources (passive / no target touch):
      * in-scope subdomains resolving to non-Cloudflare IPs (unproxied leak)
      * SPF ip4:/ip6: literals and MX host IPs on the apex
      * Shodan cert search: ssl.cert.subject.CN:"domain" -> non-CF IPs
    Confirmation (active, touches candidate IP): spoofed Host header.
    Every candidate is also enriched with ASN/org (IPinfo, if a token is
    configured) so the report shows who actually hosts the leaked origin.

    `client` (cert-verified) is used for the Shodan API lookup; `probe_client`
    (unverified) is used to touch candidate origin IPs directly, since those
    rarely present a cert matching the spoofed Host header.
    """
    result = {"detected": False, "fronted": [], "candidates": {}}

    fronted = [h.subdomain for h in hosts.values()
               if not h.wildcard and any(in_cf(ip, cf_nets) for ip in h.ips)]
    result["fronted"] = sorted(fronted)
    result["detected"] = bool(fronted)
    if not result["detected"]:
        return result

    cands = defaultdict(lambda: {"sources": set(), "confirmed": False, "evidence": None})

    # 1. unproxied in-scope subdomains
    for h in hosts.values():
        if h.wildcard:
            continue
        for ip in h.ips:
            try:
                if not in_cf(ip, cf_nets) and ipaddress.ip_address(ip).is_global:
                    cands[ip]["sources"].add(f"unproxied:{h.subdomain}")
            except Exception:
                pass

    # 2. SPF + MX from apex (DNS; low-touch, active mode only)
    if active and _HAVE_DNS:
        res = get_resolver(resolver_ns)
        for d in domains:
            try:
                for rr in await res.resolve(d, "TXT"):
                    txt = "".join(s.decode(errors="ignore") for s in rr.strings)
                    if "v=spf1" in txt:
                        for tok in txt.split():
                            if tok.startswith(("ip4:", "ip6:")):
                                ip = tok.split(":", 1)[1].split("/")[0]
                                if not in_cf(ip, cf_nets):
                                    cands[ip]["sources"].add(f"spf:{d}")
            except Exception:
                pass
            try:
                for rr in await res.resolve(d, "MX"):
                    mx = str(rr.exchange).rstrip(".")
                    mxips, _ = await resolve_full(mx, resolver_ns)
                    for ip in mxips:
                        if not in_cf(ip, cf_nets):
                            cands[ip]["sources"].add(f"mx:{mx}")
            except Exception:
                pass

    # 3. Shodan cert search (passive; costs query credits)
    if keys.get("shodan"):
        for d in domains:
            try:
                r = await client.get("https://api.shodan.io/shodan/host/search",
                                    params={"key": keys["shodan"],
                                            "query": f'ssl.cert.subject.CN:"{d}"'},
                                    timeout=25)
                if r.status_code == 200:
                    for m in r.json().get("matches", []):
                        ip = m.get("ip_str")
                        if ip and not in_cf(ip, cf_nets):
                            cands[ip]["sources"].add(f"shodan-cert:{d}")
            except Exception:
                pass

    # 4. active confirmation: the cert the candidate serves, then a spoofed Host
    # header. The cert is tried first because it is much stronger evidence — an
    # IP presenting a certificate that names the target is serving the target,
    # whereas the header test only says "answered without looking like
    # Cloudflare", which a shared host or a default vhost can do by accident.
    # A cert match also settles it without sending a request beyond the
    # handshake, so the confirmed case touches the target less than before.
    if active and cands:
        primary = domains[0]
        for ip in list(cands):
            cert = await fetch_cert(ip)
            if cert:
                cands[ip]["cert"] = cert
                match = cert_matches_scope(cert, domains)
                if match:
                    cands[ip]["confirmed"] = True
                    cands[ip]["evidence"] = (
                        f"TLS cert on {ip}:443 names {match}"
                        + (f" (issuer: {cert['issuer']})" if cert.get("issuer") else ""))
                    continue
            for scheme in ("https", "http"):
                try:
                    r = await probe_client.get(f"{scheme}://{ip}", headers={"Host": primary},
                                        timeout=8, follow_redirects=False)
                    server = (r.headers.get("server") or "").lower()
                    if r.status_code < 500 and "cloudflare" not in server:
                        cands[ip]["confirmed"] = True
                        cands[ip]["evidence"] = (f"Host: {primary} -> {scheme} "
                                                 f"{r.status_code}, server={server or 'n/a'}")
                        break
                except Exception:
                    continue

    # 5. ASN/org enrichment for each candidate IP — reuses the same IPinfo
    # enrichment path as in-scope hosts, so a client can immediately see
    # who actually hosts a leaked origin (own datacenter vs. a cloud
    # provider vs. another org's shared infrastructure). IPinfo's /json
    # endpoint works keylessly, so this runs even without a token.
    ipinfo_token = keys.get("ipinfo")
    if cands:
        for ip in list(cands):
            info = await enrich_ipinfo(client, ip, ipinfo_token)
            org = info.get("org")           # e.g. "AS15169 Google LLC"
            asn = org_name = None
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    asn, org_name = parts[0], (parts[1] if len(parts) > 1 else org)
                else:
                    org_name = org
            cands[ip]["asn"] = asn
            cands[ip]["org"] = org_name

    result["candidates"] = {ip: {"sources": sorted(v["sources"]),
                                 "confirmed": v["confirmed"], "evidence": v["evidence"],
                                 "asn": v.get("asn"), "org": v.get("org"),
                                 "cert": v.get("cert")}
                            for ip, v in cands.items()}
    return result



# --------------------------------------------------------------------------- #
# Email security posture (SPF / DKIM / DMARC) — DNS, low-touch
# --------------------------------------------------------------------------- #
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]

# SPF mechanisms that each cost a DNS lookup against RFC 7208 §4.6.4's limit of
# 10. Exceeding it is a permerror — receivers may stop evaluating SPF entirely,
# which silently undoes the whole record. `ip4:`/`ip6:`/`all` cost nothing.
_SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")
SPF_MAX_LOOKUPS = 10


def parse_spf(record: str | None) -> dict:
    """Break an SPF record into the parts an operator actually reviews. Raw text
    is always kept by the caller; this is additive structure, best-effort by
    design — a malformed record yields empty lists rather than raising."""
    out = {"all_qualifier": None, "includes": [], "redirect": None,
           "ip4": [], "ip6": [], "a": [], "mx": [], "ptr": False, "exists": [],
           "lookup_count": 0, "top_level_lookup_count": 0, "mechanisms": [],
           "exceeds_lookup_limit": False, "lookup_count_complete": True}
    if not record:
        return out
    for token in record.split():
        low = token.lower()
        if low == "v=spf1":
            continue
        out["mechanisms"].append(token)
        if low.endswith("all") and len(low) <= 4:
            out["all_qualifier"] = low[0] if low[0] in "+-~?" else "+"
        elif low.startswith("include:"):
            out["includes"].append(token.split(":", 1)[1])
        elif low.startswith("redirect="):
            out["redirect"] = token.split("=", 1)[1]
        elif low.startswith("ip4:"):
            out["ip4"].append(token.split(":", 1)[1])
        elif low.startswith("ip6:"):
            out["ip6"].append(token.split(":", 1)[1])
        elif low.startswith("a:") or low == "a":
            out["a"].append(token.split(":", 1)[1] if ":" in token else "a")
        elif low.startswith("mx:") or low == "mx":
            out["mx"].append(token.split(":", 1)[1] if ":" in token else "mx")
        elif low.startswith("ptr"):
            out["ptr"] = True
        elif low.startswith("exists:"):
            out["exists"].append(token.split(":", 1)[1])
    # Bare `a` / `mx` cost a lookup too, hence counting tokens not just prefixes.
    out["lookup_count"] = sum(
        1 for t in out["mechanisms"]
        if t.lower().startswith(_SPF_LOOKUP_MECHANISMS) or t.lower() in ("a", "mx", "ptr"))
    out["top_level_lookup_count"] = out["lookup_count"]
    # RFC 7208 §4.6.4's budget of 10 spans the *whole* evaluation, including the
    # lookups made inside every `include:`/`redirect=` target. This function is
    # deliberately I/O-free, so its count is complete only when the record
    # delegates to nothing; otherwise it is a lower bound and the caller must
    # run spf_lookup_count() to get the real figure. `exceeds_lookup_limit` is
    # still sound either way — a top-level count already over 10 is definitely a
    # permerror; expansion can only push a passing record over, never under.
    out["lookup_count_complete"] = not (out["includes"] or out["redirect"])
    out["exceeds_lookup_limit"] = out["lookup_count"] > SPF_MAX_LOOKUPS
    return out


async def spf_lookup_count(record: str | None, txt_lookup,
                           max_lookups: int = SPF_MAX_LOOKUPS) -> tuple[int, bool, bool, dict]:
    """Total DNS lookups an SPF evaluation costs, expanding `include:`/`redirect=`.

    RFC 7208 §4.6.4 caps a full evaluation at 10 lookups, counting those made
    while evaluating referenced records. Counting only the apex record misses the
    common real-world permerror: a handful of `include:`s that each pull in
    several more lookups. Returns
    `(count, complete, exceeded, unusable)`.

    `unusable` maps each target the walk could not get an SPF record from to why
    — `"no_spf_record"` or `"lookup_failed"`. These used to be skipped silently,
    but an `include:` that resolves to nothing usable is a permerror in its own
    right, and the caller diagnoses them further (a target whose *name* does not
    exist is a different and more serious problem than one that simply publishes
    no SPF).

    `txt_lookup` is the caller's async TXT resolver returning `(records, failed)`
    — reused rather than taking a resolver directly so this inherits the caller's
    TCP-retry and NXDOMAIN handling, and so tests can stub it.

    Termination without a visited-set: every queued target was reached through a
    mechanism that itself cost a counted lookup, so the queue can never hold more
    entries than `count`, and we stop the moment `count` exceeds the limit. An
    `include:` cycle therefore ends after ~11 lookups instead of looping. Because
    duplicate paths are counted rather than collapsed, the figure matches what a
    receiver actually spends; a per-domain cache keeps the DNS traffic to one
    query per distinct target.

    Failure is reported, never guessed: if a TXT lookup inside the expansion
    fails, `complete` comes back False so the caller can decline to claim
    compliance. `exceeded=True` is definitive regardless of `complete` (the count
    is a lower bound, so over-the-limit stays over the limit).
    """
    if not record:
        return 0, True, False, {}

    count, complete = 0, True
    unusable: dict[str, str] = {}
    cache: dict[str, str | None] = {}
    queue = [parse_spf(record)]
    while queue:
        p = queue.pop(0)
        count += p["lookup_count"]
        if count > max_lookups:
            # A lower bound above the cap is still a definitive permerror, so
            # stop here rather than resolving the rest of the tree.
            return count, False, True, unusable
        targets = list(p["includes"]) + ([p["redirect"]] if p["redirect"] else [])
        for target in targets:
            norm = target.lower().rstrip(".")
            if norm in cache:
                sub = cache[norm]
            else:
                recs, failed = await txt_lookup(target)
                if failed:
                    complete = False
                    cache[norm] = None
                    unusable[norm] = "lookup_failed"
                    continue
                sub = next((t for t in recs if t.lower().startswith("v=spf1")), None)
                cache[norm] = sub
            # An include: whose target yields no SPF record is a permerror — the
            # mechanism can never match. Record it; the lookup that got us here
            # is already counted and there is nothing further to expand.
            if sub:
                queue.append(parse_spf(sub))
            else:
                unusable.setdefault(norm, "no_spf_record")
    return count, complete, count > max_lookups, unusable


async def classify_spf_includes(unusable: dict, resolver_ns) -> list:
    """Diagnose the `include:`/`redirect=` targets SPF expansion couldn't use.

    A plain TXT lookup makes three very different situations look alike, so each
    unusable target gets one follow-up resolution:

      * **nxdomain** — the target's *name* does not exist. A permerror, and the
        serious case: if that domain is registrable, whoever registers it can
        publish `v=spf1 +all` and have their mail pass SPF for the domain that
        includes it. The closest still-existing zone is recorded as evidence.
      * **no_spf** — the name exists but publishes no SPF record. A permerror;
        the mechanism can never match, but nobody can hijack it.
      * **lookup_failed** — timeout/SERVFAIL. Inconclusive, and reported as such
        rather than being folded into either real state.

    Only the few targets that already failed are re-queried, and dead includes
    are rare, so this costs almost nothing in practice.
    """
    out = []
    for target, reason in sorted(unusable.items()):
        if reason == "lookup_failed":
            out.append({"target": target, "state": "lookup_failed", "closest_zone": None})
            continue
        # cname_target_status() asks for A/AAAA, so NoAnswer ("the name exists,
        # just not with this type") correctly reads as "resolves" for a target
        # that only ever publishes TXT.
        status, closest_zone = await cname_target_status(target, resolver_ns)
        state = {"nxdomain": "nxdomain", "resolves": "no_spf"}.get(status, "lookup_failed")
        out.append({"target": target, "state": state, "closest_zone": closest_zone})
    return out


# --------------------------------------------------------------------------- #
# Vendor fingerprinting from records lrecon already fetches. Same table idiom as
# MAIL_PROVIDER_PATTERNS / _IDP_PATTERNS / TAKEOVER_SIGS: (label, substrings).
#
# Purely informational — none of this touches the grade. Using a managed DMARC
# service is good practice, not a finding; folding it into `issues` would make
# the grade meaningless, the same reasoning that keeps plain MTA-STS absence out.
# --------------------------------------------------------------------------- #

# Who receives the DMARC aggregate/forensic reports. This is the "is anyone
# actually watching?" signal: a managed platform means spoofing attempts and
# lookalike sending are being collected and reviewed, not just policy-enforced.
DMARC_REPORT_VENDORS = [
    ("Red Sift OnDMARC",   ["redsift.cloud", "ondmarc.com", "redsift.com"]),
    ("dmarcian",           ["dmarcian.com", "dmarcian.eu"]),
    ("Valimail",           ["valimail.com", "vali.email"]),
    ("Agari",              ["agari.com"]),
    ("Proofpoint",         ["proofpoint.com", "emaildefense.proofpoint.com"]),
    ("Mimecast",           ["mimecast.com"]),
    ("EasyDMARC",          ["easydmarc.com"]),
    ("URIports",           ["uriports.com"]),
    ("Postmark",           ["dmarc.postmarkapp.com", "postmarkapp.com"]),
    ("Fraudmarc",          ["fraudmarc.com"]),
    ("Netcraft",           ["netcraft.com"]),
    ("Cloudflare",         ["dmarc-reports.cloudflare.com", "cloudflare.com"]),
    ("Google",             ["google.com", "googlemail.com"]),
    ("Microsoft",          ["microsoft.com", "protection.outlook.com"]),
    ("Skysnag",            ["skysnag.com"]),
    ("Sendmarc",           ["sendmarc.com"]),
]

# What the org sends mail through, from its SPF include: targets. For an
# authorized assessment this is the pretext surface — a target that sends via
# Docusign or Zendesk gives a phishing lure that fits their normal mail flow.
SPF_SENDER_VENDORS = [
    ("Microsoft 365",      ["spf.protection.outlook.com", "protection.outlook.com"]),
    ("Google Workspace",   ["_spf.google.com", "aspmx.googlemail.com"]),
    ("SendGrid",           ["sendgrid.net", "sendgrid.com"]),
    ("Mailgun",            ["mailgun.org", "mailgun.com"]),
    ("Mailchimp/Mandrill", ["mailchimp.com", "mandrillapp.com", "mcsv.net"]),
    ("Amazon SES",         ["amazonses.com"]),
    ("Salesforce",         ["salesforce.com", "exacttarget.com", "pardot.com"]),
    ("HubSpot",            ["hubspot.com", "hubspotemail.net"]),
    ("Marketo",            ["mktomail.com", "marketo.com"]),
    ("Zendesk",            ["zendesk.com"]),
    ("Freshdesk",          ["freshdesk.com", "freshemail.io"]),
    ("Intercom",           ["intercom.io", "intercommail.com"]),
    ("Docusign",           ["docusign.net", "docusign.com"]),
    ("Atlassian",          ["atlassian.net", "atlassian.com"]),
    ("ServiceNow",         ["service-now.com"]),
    ("Postmark",           ["spf.mtasv.net", "postmarkapp.com"]),
    ("SparkPost",          ["sparkpostmail.com", "messagesystems.com"]),
    ("Zoho",               ["zoho.com", "zohomail.com"]),
    ("Klaviyo",            ["klaviyo.com"]),
    ("Qualtrics",          ["qualtrics.com"]),
    ("Braze",              ["braze.com"]),
    ("Adobe",              ["adobe.com", "marketo.com"]),
]

# Which MAIL_PROVIDER_PATTERNS entries are inbound security gateways rather than
# mailbox hosts. A gateway is the difference between "mail lands in the inbox"
# and "mail is scanned, sandboxed and possibly quarantined first".
MAIL_SECURITY_GATEWAYS = {"Proofpoint", "Mimecast", "Barracuda",
                          "Cisco Secure Email (IronPort)"}


def _classify_vendor(value: str, table) -> str | None:
    """First vendor whose fingerprint appears in `value`, or None.

    Matched against the URI's host portion, not the whole string, so an
    attacker-chosen lookalike (`rua=mailto:x@notredsift.cloud.evil.com`) cannot
    borrow a vendor's name — the label has to sit on a real domain boundary.
    """
    host = _uri_host(value)
    if not host:
        return None
    for label, needles in table:
        for needle in needles:
            needle = needle.lower().strip(".")
            if host == needle or host.endswith("." + needle):
                return label
    return None


def _uri_host(value: str) -> str:
    """Host portion of a DMARC reporting URI or an SPF include target.

    DMARC `rua=` entries are URIs (`mailto:dmarc@example.com!10m`); include
    targets are bare hostnames. Both reduce to a hostname to match on.
    """
    v = (value or "").strip().lower()
    if not v:
        return ""
    v = v.split("!", 1)[0]                     # drop a DMARC size limit
    if "://" in v:
        v = v.split("://", 1)[1]
    elif v.startswith("mailto:"):
        v = v[len("mailto:"):]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    return v.split("/", 1)[0].split(":", 1)[0].strip(".")


def classify_dmarc_vendors(dmarc_parsed: dict) -> list:
    """Managed DMARC platforms receiving this domain's reports, deduped."""
    out = []
    for uri in (dmarc_parsed.get("rua") or []) + (dmarc_parsed.get("ruf") or []):
        vendor = _classify_vendor(uri, DMARC_REPORT_VENDORS)
        if vendor and vendor not in out:
            out.append(vendor)
    return out


def classify_spf_vendors(spf_parsed: dict) -> list:
    """Third-party senders authorised by this domain's SPF, deduped."""
    out = []
    targets = list(spf_parsed.get("includes") or [])
    if spf_parsed.get("redirect"):
        targets.append(spf_parsed["redirect"])
    for target in targets:
        vendor = _classify_vendor(target, SPF_SENDER_VENDORS)
        if vendor and vendor not in out:
            out.append(vendor)
    return out


def phishing_posture(entry: dict, mail_infra: list | None = None) -> dict:
    """What a domain's published email posture means for a phishing assessment.

    Answers the question an operator actually has — "if I send as this domain, or
    from a lookalike, what happens?" — from the records already collected, and
    keeps the structured inputs beside the prose so the conclusion can be audited
    rather than taken on trust.

    Describes likelihood, never guarantees an outcome. No DNS record supports
    "will be blocked": receivers honour DMARC to varying degrees, and this goes
    into a client deliverable.
    """
    dp = entry.get("dmarc_parsed") or {}
    policy, pct = dp.get("p"), dp.get("pct")
    partial = pct is not None and pct < 100
    enforced = policy in ("quarantine", "reject") and not partial
    monitored_by = classify_dmarc_vendors(dp)
    gateway = next((e.get("provider") for e in (mail_infra or [])
                    if e.get("provider") in MAIL_SECURITY_GATEWAYS), None)

    if not entry.get("dmarc"):
        spoof = ("no DMARC published — the exact domain can be spoofed outright")
    elif policy == "none":
        spoof = ("`p=none` — DMARC is monitoring-only, so the exact domain can "
                 "still be spoofed")
    elif enforced:
        spoof = (f"`p={policy}` at full coverage — spoofing the exact domain should "
                 f"fail at receivers honouring DMARC")
    elif partial:
        spoof = (f"`p={policy}` but `pct={pct}` — enforcement applies to only "
                 f"{pct}% of mail, so some spoofed mail still lands")
    else:
        spoof = f"`p={policy or 'unset'}` — enforcement unclear"

    if monitored_by:
        watch = (f"aggregate reporting to {', '.join(monitored_by)}, so lookalike "
                 f"and spoofed sending is likely to be detected and reviewed")
    elif dp.get("rua"):
        watch = ("aggregate reporting is configured, so spoofing attempts are "
                 "being collected")
    else:
        watch = ("no aggregate reporting configured — spoofing attempts are "
                 "unlikely to be noticed by the domain owner")

    parts = [spoof, watch]
    if gateway:
        parts.append(f"inbound mail is filtered by {gateway}, which may quarantine "
                     f"lookalike-domain mail on arrival")
    return {"enforced": bool(enforced), "policy": policy, "pct": pct,
            "monitored_by": monitored_by, "gateway": gateway,
            "senders": entry.get("spf_vendors") or [],
            "summary": "; ".join(parts) + "."}


def parse_dmarc(record: str | None) -> dict:
    """Tag=value breakdown of a DMARC record (p/sp/pct/rua/ruf/adkim/aspf/fo)."""
    out = {"p": None, "sp": None, "pct": None, "rua": [], "ruf": [],
           "adkim": None, "aspf": None, "fo": None}
    if not record:
        return out
    for part in record.split(";"):
        if "=" not in part:
            continue
        tag, _, val = part.strip().partition("=")
        tag, val = tag.strip().lower(), val.strip()
        if tag in ("p", "sp", "adkim", "aspf", "fo"):
            out[tag] = val.lower() if tag in ("p", "sp") else val
        elif tag == "pct":
            try:
                out["pct"] = int(val)
            except ValueError:
                pass
        elif tag in ("rua", "ruf"):
            out[tag] = [u.strip() for u in val.split(",") if u.strip()]
    return out


# The only modes RFC 8461 §3.2 defines. Anything else — including a policy file
# that never states one — leaves the policy unenforceable, so the mode is what
# decides whether a published MTA-STS record actually protects anything.
_MTA_STS_MODES = ("enforce", "testing", "none")


async def _fetch_mta_sts_policy(client, domain: str) -> dict | None:
    """Fetch and parse the MTA-STS policy file. RFC 8461 fixes its location at
    `https://mta-sts.{domain}/.well-known/mta-sts.txt`, so this is a single GET
    of a standards-defined endpoint the domain publishes on purpose.

    Returns None only when the file could not be retrieved. A retrieved file is
    returned as parsed, valid or not — judging it belongs at the decision point
    in email_security(), which has to tell "unreachable" and "published but
    unusable" apart because the remedies differ.
    """
    try:
        r = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                             timeout=10, follow_redirects=True)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    policy = {"mx": []}
    for line in (r.text or "")[:8000].splitlines():
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip().lower(), val.strip()
        if key == "mode":
            policy["mode"] = val.lower()
        elif key == "mx":
            policy["mx"].append(val.lower())
        elif key in ("version", "max_age"):
            policy[key] = val
    # Note: `policy` is always truthy (it is seeded with a key), so returning it
    # here says only "the file was fetched", never "the file is usable".
    return policy


async def email_security(domain: str, resolver_ns, client=None) -> dict:
    """
    SPF/DKIM/DMARC posture for a domain. The full verbatim records are kept
    (`spf`, `dmarc`, `dkim_record`) alongside a parsed breakdown
    (`spf_parsed`, `dmarc_parsed`) and the matched DKIM selector, so a reviewer
    can audit *why* a grade was assigned without re-querying DNS.
    """
    if not _HAVE_DNS:
        return {}
    res = get_resolver(resolver_ns)
    out = {"domain": domain, "spf": None, "dmarc": None, "dkim": False,
           "dkim_selector": None, "dkim_record": None,
           "dkim_selectors_checked": list(DKIM_SELECTORS),
           "spf_parsed": {}, "dmarc_parsed": {}, "issues": [],
           "mta_sts": None, "mta_sts_policy": None, "mta_sts_mode": None,
           "tls_rpt": None, "lookup_errors": [],
           "spf_include_health": [], "spf_vendors": [], "dmarc_vendors": []}

    async def txt(name):
        """TXT records for `name`, plus whether the lookup itself failed.

        Returns (records, failed). The distinction matters for the report: an
        apex TXT set that times out is NOT the same as a domain publishing no
        SPF, and reporting "No SPF record" for a failed lookup would put a false
        finding in a client deliverable.

        Retries over TCP when the UDP attempt fails, because a real corporate
        apex often carries enough SaaS verification records to exceed UDP's
        512-byte limit — the truncated-response case, where SPF is exactly what
        goes missing.
        """
        for kwargs in ({}, {"tcp": True}):
            try:
                answer = await res.resolve(name, "TXT", **kwargs)
                return ["".join(s.decode(errors="ignore") for s in rr.strings)
                        for rr in answer], False
            except Exception as e:
                # NXDOMAIN / NoAnswer are real "not published" answers, not
                # failures — no point retrying those over TCP.
                if type(e).__name__ in ("NXDOMAIN", "NoAnswer"):
                    return [], False
                last = e
        out["lookup_errors"].append(f"{name} TXT: {type(last).__name__}")
        return [], True

    spf_records, spf_failed = await txt(domain)
    spf = next((t for t in spf_records if "v=spf1" in t), None)
    out["spf"] = spf
    out["spf_parsed"] = parse_spf(spf)
    if not spf and spf_failed:
        out["issues"].append("SPF lookup failed (inconclusive — DNS error, not "
                             "confirmation that SPF is absent)")
    elif not spf:
        out["issues"].append("No SPF record (spoofing risk)")
    elif "+all" in spf:
        out["issues"].append("SPF +all — permits any sender (critical)")
    elif "~all" not in spf and "-all" not in spf:
        out["issues"].append("SPF missing hard/soft fail (~all/-all)")
    if spf:
        # Expand include:/redirect= so the lookup budget is measured the way a
        # receiver spends it. Without this the count is top-level only, and the
        # usual real permerror — a few includes that each pull in several more
        # lookups — goes unreported while the record looks compliant.
        total, complete, exceeded, unusable = await spf_lookup_count(spf, txt)
        out["spf_parsed"]["lookup_count"] = total
        out["spf_parsed"]["lookup_count_complete"] = complete
        out["spf_parsed"]["exceeds_lookup_limit"] = exceeded
        # Diagnose the include: targets the walk couldn't use. A dead include is
        # a permerror, and one whose name no longer exists may be registrable —
        # in which case whoever takes the domain can authorise their own mail.
        out["spf_include_health"] = await classify_spf_includes(unusable, resolver_ns)
        for inc in out["spf_include_health"]:
            if inc["state"] == "nxdomain":
                out["issues"].append(
                    f"SPF include:{inc['target']} does not exist (NXDOMAIN) — permerror "
                    f"(risk); if that domain is registrable, whoever registers it can "
                    f"publish SPF authorising their own mail for this domain"
                    + (f" [closest existing zone: {inc['closest_zone']}]"
                       if inc.get("closest_zone") else ""))
            elif inc["state"] == "no_spf":
                out["issues"].append(
                    f"SPF include:{inc['target']} publishes no SPF record — permerror, "
                    f"the mechanism can never match")
            else:
                out["issues"].append(
                    f"SPF include:{inc['target']} could not be checked (DNS error) — "
                    f"inconclusive, not confirmation that it is broken")
    out["spf_vendors"] = classify_spf_vendors(out["spf_parsed"])
    if out["spf_parsed"].get("exceeds_lookup_limit"):
        out["issues"].append(
            f"SPF exceeds {SPF_MAX_LOOKUPS}-DNS-lookup limit "
            f"({'≥' if not out['spf_parsed']['lookup_count_complete'] else ''}"
            f"{out['spf_parsed']['lookup_count']}, includes expanded) — permerror, "
            f"SPF may be ignored (risk)")
    elif not out["spf_parsed"].get("lookup_count_complete"):
        out["issues"].append(
            "SPF lookup count incomplete (a DNS lookup inside an include: failed) "
            "— cannot confirm the record stays within "
            f"{SPF_MAX_LOOKUPS} lookups")
    if out["spf_parsed"].get("ptr"):
        out["issues"].append("SPF uses deprecated ptr mechanism (RFC 7208 discourages)")

    dmarc_records, dmarc_failed = await txt(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_records if "v=DMARC1" in t), None)
    out["dmarc"] = dmarc
    out["dmarc_parsed"] = parse_dmarc(dmarc)
    if not dmarc and dmarc_failed:
        out["issues"].append("DMARC lookup failed (inconclusive — DNS error, not "
                             "confirmation that DMARC is absent)")
    elif not dmarc:
        out["issues"].append("No DMARC record (spoofing risk)")
    elif "p=none" in dmarc:
        out["issues"].append("DMARC p=none — monitoring only, no enforcement")
    out["dmarc_vendors"] = classify_dmarc_vendors(out["dmarc_parsed"])
    dp = out["dmarc_parsed"]
    if dmarc:
        if dp.get("pct") is not None and dp["pct"] < 100:
            out["issues"].append(
                f"DMARC pct={dp['pct']} — policy applied to only {dp['pct']}% of mail")
        if dp.get("sp") == "none" and dp.get("p") in ("quarantine", "reject"):
            out["issues"].append("DMARC sp=none — subdomains unprotected despite enforced p=")
        if not dp.get("rua"):
            out["issues"].append("DMARC has no rua= aggregate reporting address")

    for sel in DKIM_SELECTORS:
        recs, _ = await txt(f"{sel}._domainkey.{domain}")
        match = next((t for t in recs if "v=DKIM1" in t or "k=rsa" in t), None)
        if match:
            out["dkim"] = True
            out["dkim_selector"] = sel
            out["dkim_record"] = match
            break
    if not out["dkim"]:
        out["issues"].append("No DKIM on common selectors (inconclusive)")

    # ---- SMTP transport security: MTA-STS + TLS-RPT ----
    # SPF/DKIM/DMARC authenticate the *message*; MTA-STS protects the
    # *connection* by telling senders to require TLS with a valid certificate
    # for this domain. Without it, STARTTLS is strippable by an active network
    # attacker and mail silently downgrades to plaintext.
    #
    # Deliberately NOT raising an issue for plain absence: most domains publish
    # no MTA-STS, and adding that to `issues` would push nearly every domain to
    # WARN and make the grade meaningless. Absence is reported as a field; only
    # a *misconfigured* policy (published but unreachable, or not enforcing) is
    # an issue, since that is a real defect rather than a feature not adopted.
    sts_records, _ = await txt(f"_mta-sts.{domain}")
    out["mta_sts"] = next((t for t in sts_records if "v=STSv1" in t), None)
    tlsrpt_records, _ = await txt(f"_smtp._tls.{domain}")
    out["tls_rpt"] = next((t for t in tlsrpt_records if "v=TLSRPTv1" in t), None)
    out["mta_sts_policy"] = None
    out["mta_sts_mode"] = None
    if out["mta_sts"] and client is not None:
        policy = await _fetch_mta_sts_policy(client, domain)
        out["mta_sts_policy"] = policy
        mode = (policy or {}).get("mode")
        # Only record a mode the RFC defines: a garbage value (or a catch-all
        # page that parsed into nothing) must not reach the report looking like
        # a real policy setting.
        out["mta_sts_mode"] = mode if mode in _MTA_STS_MODES else None
        if policy is None:
            out["issues"].append(
                "MTA-STS record published but the policy file is unreachable — "
                "senders fall back to opportunistic (strippable) TLS")
        elif out["mta_sts_mode"] is None:
            # Fetched but unusable — e.g. a catch-all 200 serving the app's index
            # page. Distinct from unreachable: the endpoint answers, so the
            # operator has to fix the file's content, not its availability.
            out["issues"].append(
                "MTA-STS policy file served but invalid (no usable mode=) — "
                "the published record is not enforceable")
        elif out["mta_sts_mode"] == "testing":
            out["issues"].append(
                "MTA-STS mode=testing — TLS failures are reported, not enforced")
        elif out["mta_sts_mode"] == "none":
            out["issues"].append("MTA-STS mode=none — the policy is explicitly disabled")

    sev = len([i for i in out["issues"] if "risk" in i or "critical" in i])
    out["grade"] = "FAIL" if sev else ("WARN" if out["issues"] else "PASS")
    return out



# --------------------------------------------------------------------------- #
# DNS records (A/AAAA/MX/NS/SOA) — apex-level snapshot for the report's own
# "DNS records" section. Distinct from resolve_full() (per-subdomain A/AAAA/
# CNAME used in Phase 2) and from email_security() above (which only surfaces
# the SPF/DMARC/DKIM TXT records, not the rest of the zone). A DNS query
# against the domain's own authoritative nameservers is the same "DNS only"
# touch tier as Phase 2 resolution, so this is gated the same way (not
# --passive-only), not run alongside the keyless RDAP/WHOIS lookup above.
# --------------------------------------------------------------------------- #
async def dns_lookup(domain: str, resolver_ns) -> dict:
    out = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "soa": None}
    if not _HAVE_DNS:
        return out
    res = get_resolver(resolver_ns)

    async def q(rtype):
        try:
            return await res.resolve(domain, rtype)
        except Exception:
            return None

    a, aaaa, mx, nsrr, txt, soa = await asyncio.gather(
        q("A"), q("AAAA"), q("MX"), q("NS"), q("TXT"), q("SOA"))
    if a:
        out["a"] = sorted(str(r) for r in a)
    if aaaa:
        out["aaaa"] = sorted(str(r) for r in aaaa)
    if mx:
        out["mx"] = sorted(({"priority": r.preference, "host": str(r.exchange).rstrip(".").lower()}
                            for r in mx), key=lambda m: m["priority"])
    if nsrr:
        out["ns"] = sorted(str(r).rstrip(".").lower() for r in nsrr)
    if txt:
        out["txt"] = ["".join(s.decode(errors="ignore") for s in r.strings) for r in txt]
    if soa:
        out["soa"] = str(soa[0].mname).rstrip(".").lower()
    return out


# --------------------------------------------------------------------------- #
# DNS zone transfer (AXFR) — a misconfiguration check, not an exploit. An
# authoritative server that answers AXFR to the world hands over the entire
# zone: every internal hostname, every staging/admin record that was never
# meant to be enumerable, in one query. That collapses subdomain discovery
# completely, which is why it's a critical finding when it lands.
#
# One DNS query per nameserver against the domain's own authoritative servers —
# the same touch tier as dns_lookup() above, and gated the same way.
#
# Note: AXFR is TCP/53, which sandboxed environments block outright (the same
# class of restriction already documented for WHOIS port 43 and crt.sh's
# Postgres replica on 5432). A blocked transfer is reported as an error per
# nameserver, never as "no transfer allowed" — those are different facts.
# --------------------------------------------------------------------------- #
try:
    import dns.asyncquery, dns.message, dns.zone
    _HAVE_XFR = True
except Exception:                                  # pragma: no cover - env dependent
    _HAVE_XFR = False

AXFR_RECORD_CAP = 500          # names kept for the report; the count is exact

# Whether a failed transfer means "the server answered and declined" or "we
# never got an answer". Only the first is evidence that transfers are actually
# restricted; a timeout says nothing about the server's policy. Anything
# unrecognised is treated as inconclusive on purpose — claiming a refusal we
# cannot prove would turn a blocked network path into a clean bill of health.
_XFR_REFUSED_NAMES = ("TransferError", "XFRRefused", "NoAnswer", "FormError",
                      "Refused", "NotAuthoritative", "NoNS")
_XFR_UNREACHABLE_NAMES = ("Timeout", "TimeoutError", "ConnectionRefusedError",
                          "ConnectionResetError", "ConnectionError", "OSError",
                          "EOFError", "CancelledError", "gaierror")


async def zone_transfer(domain: str, ns_names, resolver_ns) -> dict:
    """Attempt AXFR against each of the domain's authoritative nameservers.

    Returns {attempted, transferred: {ns: record_count}, refused, records,
    errors, truncated}. `transferred` being non-empty is the finding.

    `refused` and `errors` are kept apart deliberately: a server that answers
    and declines is correctly configured, while one we could not reach tells us
    nothing. Folding the second into the first would report a blocked network
    path as "transfers refused" — a false negative on a critical check.
    """
    out = {"attempted": [], "transferred": {}, "refused": {}, "records": [],
           "errors": {}, "truncated": False}
    if not (_HAVE_DNS and _HAVE_XFR) or not ns_names:
        return out
    res = get_resolver(resolver_ns)

    for ns_name in ns_names:
        ns = str(ns_name).rstrip(".").lower()
        ips = []
        for rtype in ("A", "AAAA"):
            try:
                ips = [str(r) for r in await res.resolve(ns, rtype)]
            except Exception:
                continue
            if ips:
                break
        if not ips:
            out["errors"][ns] = "nameserver did not resolve"
            continue
        out["attempted"].append(ns)
        try:
            zone = dns.zone.Zone(domain)
            query = dns.message.make_query(domain, "AXFR")
            await dns.asyncquery.inbound_xfr(ips[0], zone, query,
                                             timeout=5, lifetime=20)
        except Exception as e:
            kind = type(e).__name__
            if kind in _XFR_REFUSED_NAMES:
                out["refused"][ns] = kind
            else:
                out["errors"][ns] = kind
            continue
        names = []
        for node in zone.nodes:
            label = node.to_text() if hasattr(node, "to_text") else str(node)
            names.append(domain if label in ("@", "") else f"{label}.{domain}")
        out["transferred"][ns] = len(names)
        for fqdn in sorted(set(names))[:AXFR_RECORD_CAP]:
            if fqdn not in out["records"]:
                out["records"].append(fqdn)
        if len(set(names)) > AXFR_RECORD_CAP:
            out["truncated"] = True
    return out



# --------------------------------------------------------------------------- #
# Mail infrastructure identification — resolves each MX host's IP and
# enriches it via IPinfo (ASN/org/country, reusing the same enrichment used
# for in-scope hosts), then labels well-known managed-email providers by
# hostname so the report reads "Google Workspace" / "Microsoft 365" rather
# than an opaque MX hostname. One entry per unique MX host — several
# priority tiers commonly share a provider's pool (e.g. multiple
# *.protection.outlook.com records).
# --------------------------------------------------------------------------- #
MAIL_PROVIDER_PATTERNS = [
    ("Google Workspace",               ["google.com", "googlemail.com"]),
    ("Microsoft 365",                  ["outlook.com", "protection.outlook.com"]),
    ("Proofpoint",                     ["pphosted.com", "proofpoint.com"]),
    ("Mimecast",                       ["mimecast.com"]),
    ("Barracuda",                      ["barracudanetworks.com"]),
    ("Cisco Secure Email (IronPort)",  ["iphmx.com", "ppe-hosted.com"]),
    ("Zoho Mail",                      ["zoho.com", "zohomail.com"]),
    ("Amazon SES / WorkMail",          ["amazonaws.com", "awsapps.com"]),
    ("Yandex Mail",                    ["yandex.net", "yandex.ru"]),
]


def _classify_mail_provider(mx_host: str) -> str | None:
    h = mx_host.lower()
    for name, patterns in MAIL_PROVIDER_PATTERNS:
        if any(p in h for p in patterns):
            return name
    return None


async def mail_infra_lookup(client, mx_records: list, ipinfo_token: str | None, resolver_ns) -> list:
    out = []
    seen = set()
    for mx in mx_records:
        host = mx["host"]
        if host in seen:
            continue
        seen.add(host)
        entry = {"host": host, "priority": mx["priority"], "ips": [],
                 "provider": _classify_mail_provider(host), "asn": None, "org": None, "country": None}
        if _HAVE_DNS:
            try:
                res = get_resolver(resolver_ns)
                entry["ips"] = sorted(str(r) for r in await res.resolve(host, "A"))
            except Exception:
                pass
        if entry["ips"]:
            info = await enrich_ipinfo(client, entry["ips"][0], ipinfo_token)
            org = info.get("org")           # e.g. "AS15169 Google LLC"
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    entry["asn"] = parts[0]
                    entry["org"] = parts[1] if len(parts) > 1 else org
                else:
                    entry["org"] = org
            entry["country"] = info.get("country")
        out.append(entry)
    return out


# --------------------------------------------------------------------------- #
# Passive authentication-surface mapping — which SSO/OIDC identity provider a
# host federates to, from the standard OIDC discovery document and common
# well-known paths. DISCOVERY ONLY: a single GET of public, standards-defined
# metadata endpoints (RFC 8414 / OpenID Connect Discovery) — no credential
# probing, no login attempts, no account enumeration. It tells a client which
# IdP fronts their auth (Okta, Entra/Azure AD, Auth0, Ping, ADFS, Google) so
# federation/conditional-access review can start from fact, not guesswork.
# ATT&CK: T1590 (Gather Victim Network Info) / T1596 (Search Open Technical
# Databases) — reconnaissance, not access.
# --------------------------------------------------------------------------- #
_IDP_PATTERNS = (
    ("Okta",              ("okta.com", "oktapreview.com", "okta-emea.com")),
    ("Microsoft Entra ID", ("login.microsoftonline.com", "sts.windows.net",
                            "microsoftonline.com", "windows.net")),
    ("Auth0",             ("auth0.com",)),
    ("Ping Identity",     ("pingone.com", "pingidentity.com", "ping-eng.com")),
    ("Google",            ("accounts.google.com", "google.com")),
    ("OneLogin",          ("onelogin.com",)),
    ("ADFS",              ("/adfs/",)),
    ("Keycloak",          ("/realms/", "/auth/realms/")),
)

_OIDC_WELL_KNOWN = "/.well-known/openid-configuration"


def _fingerprint_idp(oidc: dict, final_url: str) -> str | None:
    """Match issuer/endpoint hosts against known IdP domains. `oidc` is the
    parsed discovery document; `final_url` is where the request landed
    (captures redirect-to-IdP even when the JSON is unavailable)."""
    haystack = " ".join([
        (oidc or {}).get("issuer", "") or "",
        (oidc or {}).get("authorization_endpoint", "") or "",
        (oidc or {}).get("token_endpoint", "") or "",
        final_url or "",
    ]).lower()
    for name, needles in _IDP_PATTERNS:
        if any(n in haystack for n in needles):
            return name
    return None


async def auth_surface(client, host: str) -> dict:
    """
    Probe a host's OIDC discovery document and report the identity provider
    fronting it, if any. Returns {host, idp, oidc_config_url, endpoints} or
    {} when nothing authentication-related is exposed. Best-effort and
    passive: one HTTPS GET of a public metadata path.
    """
    url = f"https://{host}{_OIDC_WELL_KNOWN}"
    try:
        r = await client.get(url, timeout=15, follow_redirects=True)
    except Exception:
        return {}
    if r.status_code != 200:
        return {}
    try:
        oidc = r.json()
    except Exception:
        return {}
    if not isinstance(oidc, dict) or not oidc.get("issuer"):
        return {}
    final_url = str(getattr(r, "url", "") or url)
    endpoints = {k: oidc.get(k) for k in
                 ("authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                  "jwks_uri", "end_session_endpoint") if oidc.get(k)}
    return {"host": host, "idp": _fingerprint_idp(oidc, final_url),
            "issuer": oidc.get("issuer"), "oidc_config_url": url,
            "endpoints": endpoints}


# security.txt (RFC 9116) — a file the organization publishes deliberately, so
# reading it is discovery, not probing. Two uses in an assessment: it names the
# disclosure channel a report should actually go to, and its Policy / Canonical /
# Acknowledgments URLs routinely point at internal or otherwise undiscovered
# hosts. An `Expires` date in the past means the contact information is, per the
# RFC, no longer to be trusted — worth flagging to the client.
_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
_SECURITY_TXT_FIELDS = ("contact", "expires", "policy", "encryption",
                        "acknowledgments", "canonical", "preferred-languages",
                        "hiring", "csaf")


async def security_txt(client, host: str) -> dict:
    """Fetch and parse security.txt for one host, or {} if not published.

    Tries the RFC 9116 well-known location first, then the legacy root path that
    predates it and is still in the wild. Multi-valued fields (Contact, Policy,
    ...) keep every entry, since the extra URLs are the interesting part.
    """
    for path in _SECURITY_TXT_PATHS:
        url = f"https://{host}{path}"
        try:
            r = await client.get(url, timeout=15, follow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        body = (r.text or "")[:20000]
        # Guard against a catch-all returning an HTML page for every path.
        if "<html" in body[:400].lower() or "contact:" not in body.lower():
            continue
        fields = defaultdict(list)
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if sep and val and key in _SECURITY_TXT_FIELDS:
                fields[key].append(val)
        if not fields.get("contact"):
            continue
        out = {"host": host, "url": url, **{k: v for k, v in fields.items()}}
        out["expired"] = _security_txt_expired(fields.get("expires"))
        return out
    return {}


def _security_txt_expired(expires) -> bool | None:
    """True/False if the Expires field parses, None if absent or unparseable —
    an unparseable date must not be reported as either state."""
    if not expires:
        return None
    raw = expires[0].strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(raw)
    except Exception:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when < datetime.now(timezone.utc)



# --------------------------------------------------------------------------- #
# Domain registration data (WHOIS via RDAP) — keyless, third-party registry
# only, never touches the target's own infrastructure. RDAP is the
# structured, JSON-based successor to WHOIS; rdap.org is a public bootstrap
# redirector to the authoritative RDAP server for whatever TLD the domain is
# under, so one endpoint covers the large majority of TLDs without needing to
# chase IANA referrals ourselves.
#
# rdap.org routes to the REGISTRY's RDAP server (e.g. Verisign for .com,
# PIR for .org), which — post-GDPR — omits registrant data entirely for
# most gTLDs; that data instead lives at the REGISTRAR's own RDAP server,
# referenced by a `rel=related` link in the registry response. rdap_lookup()
# follows that one extra hop when the registry response has no registrant
# entity, since that's what actually surfaces privacy-protection status for
# the common case (confirmed live: registry-level namecheap.com has no
# registrant entity at all; the registrar-level referral shows
# rdapConformance containing "redacted" plus a registrant vcard org of
# "Privacy service provided by Withheld for Privacy ehf").
# --------------------------------------------------------------------------- #
_PRIVACY_KEYWORDS = ("privacy", "proxy", "redacted", "withheld", "protect", "whoisguard")


def _rdap_vcard_field(entity: dict, field: str) -> str | None:
    """A jCard field (vcardArray[1] is a list of [field, params, type, value, ...]
    entries) — e.g. "fn" (name) or "org" (organization, often where a privacy
    service's own name shows up for a redacted registrant)."""
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] == field and item[3]:
            return item[3]
    return None


def _rdap_entity_name(entity: dict) -> str | None:
    return _rdap_vcard_field(entity, "fn")


def _rdap_referral_link(data: dict) -> str | None:
    """The registrar's own RDAP endpoint, if the registry response links to one."""
    for link in data.get("links", []) or []:
        if link.get("rel") == "related" and "rdap" in (link.get("type") or "").lower():
            return link.get("href")
    return None


def _parse_rdap(data: dict) -> dict:
    out = {"registrar": None, "created": None, "expires": None,
          "last_changed": None, "nameservers": [], "status": [],
          "registrant_name": None, "registrant_org": None,
          "privacy_protected": None, "privacy_provider": None}
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        if action == "registration":
            out["created"] = ev.get("eventDate")
        elif action == "expiration":
            out["expires"] = ev.get("eventDate")
        elif action == "last changed":
            out["last_changed"] = ev.get("eventDate")
    out["nameservers"] = sorted({ns["ldhName"].lower() for ns in data.get("nameservers", []) or []
                                 if ns.get("ldhName")})
    out["status"] = data.get("status") or []
    registrar = next((e for e in data.get("entities", []) or [] if "registrar" in (e.get("roles") or [])),
                     None)
    if registrar:
        out["registrar"] = _rdap_entity_name(registrar)

    registrant = next((e for e in data.get("entities", []) or [] if "registrant" in (e.get("roles") or [])),
                      None)
    if registrant:
        name = _rdap_entity_name(registrant)
        org = _rdap_vcard_field(registrant, "org")
        out["registrant_name"] = name
        out["registrant_org"] = org
        redacted_ext = bool(data.get("redacted")) or "redacted" in (data.get("rdapConformance") or [])
        looks_private = any(k in (org or "").lower() for k in _PRIVACY_KEYWORDS) or \
                        any(k in (name or "").lower() for k in _PRIVACY_KEYWORDS)
        if redacted_ext or looks_private or not name:
            out["privacy_protected"] = True
            out["privacy_provider"] = org if (org and looks_private) else None
        else:
            out["privacy_protected"] = False
    return out


async def rdap_lookup(client, domain: str) -> dict:
    """
    Overrides the shared client's default follow_redirects=False for this one
    call — rdap.org responds with a redirect to the authoritative registry
    (e.g. rdap.verisign.com for .com), confirmed live against example.com.
    Returns {} on any failure — many domains (some ccTLDs without RDAP
    support yet, typos, internal-only names) simply won't resolve. Still
    logged (once, at "no data" level) rather than silently vanishing, since
    a fully-empty WHOIS section with no explanation is confusing — the
    caller shows a placeholder row for the domain either way.

    If the registry response has no registrant entity (the common case for
    thin gTLD registries), follows the registrar's own RDAP referral link
    once to fill in registrant/privacy-protection fields — best-effort, a
    failed or missing referral just leaves those fields as "unknown" rather
    than failing the whole lookup.
    """
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", timeout=20, follow_redirects=True)
        if r.status_code != 200:
            log(f"[!] whois/rdap {domain}: no data (HTTP {r.status_code} from rdap.org)")
            return {}
        data = r.json()
        out = _parse_rdap(data)
        if out["registrant_name"] is None and out["registrant_org"] is None \
                and out["privacy_protected"] is None:
            referral = _rdap_referral_link(data)
            if referral:
                try:
                    r2 = await client.get(referral, timeout=20, follow_redirects=True)
                    if r2.status_code == 200:
                        ref = _parse_rdap(r2.json())
                        for k in ("registrant_name", "registrant_org",
                                 "privacy_protected", "privacy_provider"):
                            out[k] = ref[k]
                        for k in ("registrar", "created", "expires", "last_changed"):
                            out[k] = out[k] or ref[k]
                        out["nameservers"] = out["nameservers"] or ref["nameservers"]
                        out["status"] = out["status"] or ref["status"]
                except Exception:
                    pass   # referral hop is best-effort; registry data still returned
        return out
    except Exception as e:
        log(f"[!] whois/rdap {domain}: {e}")
    return {}


def _days_to_expiry(expires: str | None) -> int | None:
    """Whole days until the registration expires (negative if already lapsed),
    or None if there's no parseable expiry date."""
    if not expires:
        return None
    try:
        from datetime import datetime, timezone
        exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        # Fallback WHOIS/VT tiers hand back free-text, often timezone-less dates
        # (e.g. "2026-08-15"), which fromisoformat parses to a *naive* datetime;
        # subtracting the UTC-aware `now` would raise TypeError and silently drop
        # the finding. Assume UTC for any naive value so those domains still get
        # flagged.
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except Exception:
        return None


def domain_expiring_soon(expires: str | None, within_days: int = 30) -> bool:
    days = _days_to_expiry(expires)
    return days is not None and days <= within_days


def empty_whois_entry() -> dict:
    return {"registrar": None, "created": None, "expires": None, "last_changed": None,
           "nameservers": [], "status": [], "registrant_name": None, "registrant_org": None,
           "privacy_protected": None, "privacy_provider": None}


# --------------------------------------------------------------------------- #
# Classic WHOIS (port 43) — fallback for TLDs with no RDAP service at all.
# Confirmed against IANA's own canonical RDAP bootstrap registry
# (https://data.iana.org/rdap/dns.json): .io, .co, .me, and others simply
# have no RDAP entry — not a bug in rdap.org's redirector, there is no
# RDAP server to redirect to. Pure-Python sockets, RFC 3912 — no external
# `whois` binary, keeping the earlier "no system whois binary" design
# intact while still covering these TLDs. Two round trips: ask
# whois.iana.org which registry WHOIS server is authoritative for the
# TLD (the same referral every classic WHOIS client does), then query
# that server directly. Free-text parsing is necessarily best-effort —
# format varies by registry, unlike RDAP's structured JSON.
# --------------------------------------------------------------------------- #
_WHOIS_FIELD_PATTERNS = {
    "registrar": (r"registrar:\s*(.+)", r"sponsoring registrar:\s*(.+)", r"registrar name:\s*(.+)"),
    "created": (r"creation date:\s*(.+)", r"created on:\s*(.+)", r"registered on:\s*(.+)",
               r"domain registration date:\s*(.+)", r"created:\s*(.+)", r"registered:\s*(.+)"),
    "expires": (r"registry expiry date:\s*(.+)", r"expiration date:\s*(.+)",
               r"expiry date:\s*(.+)", r"registrar registration expiration date:\s*(.+)",
               r"expires:\s*(.+)", r"expires on:\s*(.+)", r"paid-till:\s*(.+)"),
    "last_changed": (r"updated date:\s*(.+)", r"last updated on:\s*(.+)", r"last modified:\s*(.+)",
                     r"changed:\s*(.+)", r"modified:\s*(.+)", r"last-update:\s*(.+)"),
}


async def _iana_whois_referral(tld: str) -> str | None:
    """The registry WHOIS server authoritative for a TLD, per IANA's own
    WHOIS server — there's no single global endpoint the way RDAP has one
    bootstrap redirector, so this referral hop is required."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("whois.iana.org", 43), timeout=10)
        try:
            writer.write(f"{tld}\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=10)
        finally:
            writer.close()
        for line in data.decode(errors="ignore").splitlines():
            if line.lower().startswith("whois:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


async def _whois43_query(server: str, domain: str) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout=15)
        try:
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()
            chunks = []
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=15)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            writer.close()
        return b"".join(chunks).decode(errors="ignore")
    except Exception:
        return None


def _parse_whois43(text: str) -> dict:
    out = empty_whois_entry()
    if not text:
        return out
    nameservers = set()
    statuses = []
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if not low or low.startswith(("%", "#", ">>>")):
            continue
        for field, patterns in _WHOIS_FIELD_PATTERNS.items():
            if out[field]:
                continue
            for pat in patterns:
                if re.match(pat, low) and ":" in stripped:
                    val = stripped.split(":", 1)[1].strip()
                    if val:
                        out[field] = val
                    break
        if low.startswith(("name server:", "nserver:")) and ":" in stripped:
            ns = stripped.split(":", 1)[1].strip().split()[0].rstrip(".").lower() \
                if stripped.split(":", 1)[1].strip() else ""
            if ns:
                nameservers.add(ns)
        elif low.startswith(("domain status:", "status:")) and ":" in stripped:
            val = stripped.split(":", 1)[1].strip()
            if val:
                statuses.append(val)
        elif low.startswith("registrant organization:") and ":" in stripped:
            out["registrant_org"] = stripped.split(":", 1)[1].strip() or None
        elif low.startswith("registrant name:") and ":" in stripped:
            out["registrant_name"] = stripped.split(":", 1)[1].strip() or None

    out["nameservers"] = sorted(nameservers)
    out["status"] = statuses
    if out["registrant_name"] or out["registrant_org"]:
        looks_private = any(k in (out["registrant_org"] or "").lower() for k in _PRIVACY_KEYWORDS) or \
                        any(k in (out["registrant_name"] or "").lower() for k in _PRIVACY_KEYWORDS)
        out["privacy_protected"] = looks_private
        if looks_private:
            out["privacy_provider"] = out["registrant_org"]
    return out


async def whois43_lookup(domain: str) -> dict:
    """Returns {} if the TLD has no discoverable WHOIS server, the query
    fails, or nothing useful was parsed out of the response."""
    tld = domain.rsplit(".", 1)[-1].lower()
    server = await _iana_whois_referral(tld)
    if not server:
        return {}
    text = await _whois43_query(server, domain)
    if not text:
        return {}
    out = _parse_whois43(text)
    return out if any(out.get(k) for k in ("registrar", "created", "expires", "nameservers")) else {}


def _merge_whois(base: dict | None, extra: dict) -> dict:
    merged = dict(base) if base else empty_whois_entry()
    for k, v in extra.items():
        if not merged.get(k):
            merged[k] = v
    return merged


async def whois_lookup(client, domain: str, vt_whois_text: str | None = None) -> dict:
    """
    Three tiers, each only filling gaps the previous one left (RDAP's
    values are never overwritten by a later tier):

    1. RDAP — structured, fast.
    2. Classic WHOIS (port 43), for TLDs with no RDAP service at all
       (.io/.co/.me and others, per IANA's own bootstrap registry).
    3. VirusTotal's own cached WHOIS text (pass the domain's `"whois"`
       field from --vt's vt_domain_intel(), if available), parsed with
       the same best-effort parser as tier 2. This tier exists because
       raw TCP/port 43 is blocked outright in some sandboxed execution
       environments (Claude Code's own remote containers included — see
       /root/.ccr/README.md's "Not supported through the proxy: ...
       raw-TCP databases"), where tier 2 silently comes back empty no
       matter what the TLD is; VT's text was fetched over HTTPS, so it
       isn't subject to that restriction.

    Result always carries a "source" field listing which tier(s)
    contributed a value, joined with "+" (e.g. "rdap+vt-whois"), or None
    if none did.
    """
    w = await rdap_lookup(client, domain)
    sources = ["rdap"] if w else []
    if not w or not w.get("registrar"):
        w43 = await whois43_lookup(domain)
        if w43:
            w = _merge_whois(w, w43)
            sources.append("whois43")
    if (not w or not w.get("registrar")) and vt_whois_text:
        w_vt = _parse_whois43(vt_whois_text)
        if any(w_vt.get(k) for k in ("registrar", "created", "expires", "nameservers")):
            w = _merge_whois(w, w_vt)
            sources.append("vt-whois")
    if not w:
        w = empty_whois_entry()
    w["source"] = "+".join(sources) or None
    return w



# --------------------------------------------------------------------------- #
# GitHub code dorking (needs token) — T1593.003
# --------------------------------------------------------------------------- #
async def github_dork(client, domain: str, token: str, limiter) -> list:
    out = []
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github.v3+json",
               "User-Agent": "lrecon"}
    for q in (f'"{domain}"', f'"{domain}" password', f'"{domain}" api_key'):
        await limiter.wait()
        try:
            r = await client.get("https://api.github.com/search/code",
                                params={"q": q, "per_page": 20}, headers=headers, timeout=25)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    out.append({"repo": item.get("repository", {}).get("full_name"),
                                "path": item.get("path"),
                                "url": item.get("html_url"),
                                "query": q})
            elif r.status_code == 403:
                log("[!] github: rate limited")
                break
        except Exception as e:
            log(f"[!] github dork: {e}")
            break
    # dedupe by url
    seen, uniq = set(), []
    for it in out:
        if it["url"] not in seen:
            seen.add(it["url"])
            uniq.append(it)
    return uniq



# --------------------------------------------------------------------------- #
# Cloud bucket enumeration (permutation + HEAD) — low-touch (hits provider)
# --------------------------------------------------------------------------- #
BUCKET_SUFFIXES = ["", "-backup", "-backups", "-dev", "-prod", "-staging", "-assets",
                   "-static", "-data", "-media", "-uploads", "-logs", "-files",
                   "-public", "-private", "-internal", "-www"]


def bucket_candidates(keywords) -> list:
    names = set()
    for kw in keywords:
        kw = kw.lower().replace(".", "-")
        for suf in BUCKET_SUFFIXES:
            names.add(f"{kw}{suf}")
    return sorted(names)


# Object keys worth calling out in a public bucket — the ones that make a
# listing a red-team finding rather than a pile of static assets: credentials,
# configs, source/database dumps, archives, keys/certs, infra state.
#
# Extensions are matched either at the end of the key OR followed by another
# suffix, because the highest-value files in the wild are usually the *variant*
# forms: `.env.production`, `.env.local`, `config.yml.bak`, `db.sql.gz`,
# `settings.ini.old`. Anchoring strictly to end-of-string misses exactly those.
_INTERESTING_OBJECT_RE = re.compile(
    r"(\.(sql|bak|backup|dump|db|sqlite3?|env|ini|cfg|conf|config|ya?ml|pem|key|"
    r"ppk|pfx|p12|crt|kdbx|tfstate|kubeconfig|htpasswd|ovpn|rdp|jks|keystore|"
    r"csv|xlsx?|docx?|pst|zip|tar|t?gz|tgz|rar|7z|war|jar|old|swp|orig)"
    r"($|[.\-_/]))|"
    r"(password|passwd|secret|credential|token|apikey|api[-_]?key|private[-_]?key|"
    r"\.git/|\.svn/|id_rsa|id_dsa|id_ecdsa|\.ssh/|\.aws/|\.npmrc|\.pypirc|"
    r"backup|dump|database|shadow|kdbx)",
    re.IGNORECASE)


def _bucket_object_url(provider: str, name: str, key: str) -> str:
    from urllib.parse import quote
    path = quote(key, safe="/")
    if provider == "s3":
        return f"https://{name}.s3.amazonaws.com/{path}"
    if provider == "gcs":
        return f"https://storage.googleapis.com/{name}/{path}"
    if provider == "azure":
        return f"https://{name}.blob.core.windows.net/{path}"
    return path


def _parse_bucket_listing(provider: str, name: str, body: str) -> dict:
    """Pull object keys/sizes out of a public bucket's listing XML so the
    report can show *what* is exposed, with direct links — read-only, from the
    listing response already in hand (no extra requests). S3 and GCS share the
    <Contents><Key>/<Size> shape; Azure uses <Blob><Name>/<Content-Length>.
    Returns {objects, object_count, interesting, bytes, truncated}; objects is
    capped for display, interesting keeps the security-relevant keys."""
    if provider == "azure":
        blocks = re.findall(r"<Blob>(.*?)</Blob>", body, re.DOTALL)
        key_re, size_re = r"<Name>(.*?)</Name>", r"<Content-Length>(\d+)</Content-Length>"
        truncated = bool(re.search(r"<NextMarker>\s*\S", body))
    else:
        blocks = re.findall(r"<Contents>(.*?)</Contents>", body, re.DOTALL)
        key_re, size_re = r"<Key>(.*?)</Key>", r"<Size>(\d+)</Size>"
        truncated = "<IsTruncated>true</IsTruncated>" in body

    objects = []
    total_bytes = 0
    for blk in blocks:
        km = re.search(key_re, blk, re.DOTALL)
        if not km:
            continue
        # The listing is XML, so metacharacters in a real key arrive escaped:
        # an object named `R&D.sql` comes back as `R&amp;D.sql`. Decode once here,
        # before the placeholder test, the interesting-key regex and the URL
        # build — otherwise the link is percent-encoded from the *escaped* text
        # (`R%26amp%3BD.sql`, a 404) and an entity mid-name can hide a sensitive
        # suffix from the regex. Strip before unescaping so that insignificant
        # XML whitespace goes but a deliberately encoded space (`&#32;`) stays.
        key = html.unescape(km.group(1).strip())
        if not key or key.endswith("/"):        # skip Azure/GCS folder placeholders
            continue
        sm = re.search(size_re, blk)
        size = int(sm.group(1)) if sm else None
        if size:
            total_bytes += size
        objects.append({"key": key, "url": _bucket_object_url(provider, name, key),
                        "size": size, "interesting": bool(_INTERESTING_OBJECT_RE.search(key))})

    interesting = [o for o in objects if o["interesting"]][:50]
    return {"object_count": len(objects), "objects": objects[:100],
            "interesting": interesting, "bytes": total_bytes, "truncated": truncated}


async def bucket_enum(client, keywords) -> list:
    out = []
    names = bucket_candidates(keywords)
    sem = asyncio.Semaphore(40)

    async def check(name):
        async with sem:
            probes = [
                ("s3", f"https://{name}.s3.amazonaws.com"),
                ("gcs", f"https://storage.googleapis.com/{name}"),
                ("azure", f"https://{name}.blob.core.windows.net/?comp=list&restype=container"),
            ]
            for provider, url in probes:
                try:
                    r = await client.get(url, timeout=8)
                    if r.status_code in (200, 403):
                        public = r.status_code == 200 and ("<ListBucketResult" in r.text
                                                           or "<EnumerationResults" in r.text
                                                           or "<Contents" in r.text)
                        entry = {"name": name, "provider": provider, "url": url,
                                 "status": r.status_code, "public": public}
                        if public:
                            # Parse the listing we already fetched so the report
                            # can surface the exposed files + direct links.
                            entry.update(_parse_bucket_listing(provider, name, r.text))
                        out.append(entry)
                except Exception:
                    pass
    await asyncio.gather(*(check(n) for n in names))
    return out



# --------------------------------------------------------------------------- #
# Breach exposure (HIBP breaches-by-domain, keyless list)
# --------------------------------------------------------------------------- #
async def hibp_breaches(client, domain: str) -> list:
    out = []
    try:
        r = await client.get("https://haveibeenpwned.com/api/v3/breaches",
                            params={"domain": domain},
                            headers={"User-Agent": "lrecon"}, timeout=20)
        if r.status_code == 200:
            for b in r.json():
                out.append({"name": b.get("Name"), "date": b.get("BreachDate"),
                            "pwned": b.get("PwnCount"),
                            "data": b.get("DataClasses", [])})
    except Exception as e:
        log(f"[!] hibp {domain}: {e}")
    return out



# --------------------------------------------------------------------------- #
# Entry-point summary — the highest-signal findings, ranked, across all phases
# --------------------------------------------------------------------------- #
ENTRY_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CVSS_SEVERITY = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"))

# Label + a rough severity for non-web ports worth flagging by name — direct
# RCE/lateral-movement-prone services (RDP, SMB, VNC, WinRM, Telnet) rank
# higher than ones that are commonly intentionally exposed (SSH, mail, DNS).
# Anything open but not in this table (e.g. a naabu hit on an odd port) still
# gets flagged, just without a friendly name, at a conservative "medium".
NON_WEB_PORT_INFO = {
    21: ("FTP", "medium"), 22: ("SSH", "low"), 23: ("Telnet", "high"),
    25: ("SMTP", "low"), 53: ("DNS", "low"), 110: ("POP3", "low"),
    111: ("RPCbind", "medium"), 135: ("MS-RPC", "medium"), 139: ("NetBIOS", "medium"),
    143: ("IMAP", "low"), 389: ("LDAP", "medium"), 445: ("SMB", "high"),
    465: ("SMTPS", "low"), 587: ("SMTP submission", "low"), 993: ("IMAPS", "low"),
    995: ("POP3S", "low"), 1433: ("MSSQL", "medium"), 1723: ("PPTP", "medium"),
    3306: ("MySQL", "medium"), 3389: ("RDP", "high"), 5432: ("PostgreSQL", "medium"),
    5900: ("VNC", "high"), 5985: ("WinRM", "high"), 6379: ("Redis", "high"),
    9200: ("Elasticsearch", "high"), 27017: ("MongoDB", "high"),
}


def _cve_severity(cvss, has_poc: bool = False) -> str:
    if cvss is None:
        sev = "medium"                               # no CVSS data (e.g. Shodan/InternetDB vulns list)
    else:
        sev = "low"
        for threshold, s in _CVSS_SEVERITY:
            if cvss >= threshold:
                sev = s
                break
    # A working public exploit is a stronger red-team signal than raw CVSS
    # alone — floor at "high" rather than leaving it at medium/low.
    if has_poc and ENTRY_SEVERITY_ORDER[sev] > ENTRY_SEVERITY_ORDER["high"]:
        sev = "high"
    return sev


def summarize_entry_points(hosts, cf, buckets, breach, github_findings, nuclei,
                           dorks=None, auth_surfaces=None, whois=None,
                           axfr=None) -> list:
    """
    Pull the findings that represent a likely initial-access vector out of the
    full result set into one ranked list, so they're stated explicitly instead
    of only implied by per-phase stats. Each entry: type, target, severity,
    summary, attck (ATT&CK technique).
    """
    out = []

    for h in hosts:
        if h.takeover:
            # Severity comes from the structured confidence rather than a phrase
            # match on the summary text. Every detection path sets the field, so
            # the "high" default is only reached by a hand-built Host — mid-scale
            # rather than critical, since an unlabelled lead carries no evidence
            # about how strong it is.
            sev = {"confirmed": "critical", "likely": "critical",
                   "possible": "high"}.get(h.takeover_confidence, "high")
            out.append({"type": "subdomain-takeover", "target": h.subdomain, "severity": sev,
                       "summary": h.takeover, "attck": "T1584.001",
                       "confidence": h.takeover_confidence})

    for domain, result in (axfr or {}).items():
        if not (result or {}).get("transferred"):
            continue
        servers = ", ".join(result["transferred"])
        total = sum(result["transferred"].values())
        out.append({"type": "dns-zone-transfer", "target": domain, "severity": "critical",
                    "summary": f"AXFR allowed by {servers} — {total} record(s) of the "
                               f"zone disclosed, including any internal-only names",
                    "attck": "T1590.002"})

    if cf.get("detected"):
        for ip, v in cf.get("candidates", {}).items():
            if v["confirmed"]:
                out.append({"type": "cloudflare-origin-bypass", "target": ip, "severity": "high",
                           "summary": f"Origin IP reachable outside Cloudflare — WAF/DDoS bypass "
                                      f"({v['evidence']})",
                           "attck": "T1590.005"})

    for b in buckets:
        if b["public"]:
            # Fold the listing detail into the finding so the entry-points
            # table alone is actionable — an operator shouldn't have to
            # cross-reference the Cloud-storage section to know whether a
            # public bucket holds credentials or just static assets.
            n_obj = b.get("object_count")
            obj_note = ""
            if n_obj:
                obj_note = f", {n_obj} object(s)" + ("+ (truncated)" if b.get("truncated") else "")
            interesting = b.get("interesting") or []
            if interesting:
                keys = ", ".join(o["key"] for o in interesting[:5])
                more = f" +{len(interesting) - 5} more" if len(interesting) > 5 else ""
                obj_note += f" — sensitive-looking: {keys}{more}"
            sev = "critical" if interesting else "high"
            out.append({"type": "public-bucket", "target": b["name"], "severity": sev,
                       "summary": f"{b['provider']} bucket publicly listable at "
                                  f"{b['url']}{obj_note}",
                       "attck": "T1530"})

    for n in (nuclei or []):
        sev = (n.get("severity") or "").lower()
        if sev in ("critical", "high"):
            out.append({"type": "nuclei-finding", "target": n.get("host") or "?", "severity": sev,
                       "summary": f"{n.get('name') or n.get('template')} "
                                  f"({n.get('cve') or 'no CVE'}) at {n.get('matched')}",
                       "attck": "T1190"})

    for d in (dorks or []):
        out.append({"type": "dork-hit", "target": d["link"], "severity": d["severity"],
                   "summary": f"{d['category']}: {d['title']} — {d['snippet']}",
                   "attck": "T1593.002"})

    for a in (auth_surfaces or []):
        idp = a.get("idp") or "unknown IdP"
        out.append({"type": "auth-surface", "target": a["host"], "severity": "info",
                   "summary": f"OIDC/SSO endpoint exposed — federates to {idp} "
                              f"(issuer: {a.get('issuer') or '?'})",
                   "attck": "T1590"})

    known_cve_cap = 5
    for h in hosts:
        nvd = h.nvd_cves or []
        nvd_by_id = {c["id"]: c for c in nvd if c.get("id")}
        all_ids = set(h.vulns) | set(nvd_by_id)
        # DoS-only CVEs aren't useful as an initial-access lead — drop them from
        # consideration (and from severity ranking) wherever NVD data classifies
        # them as such. IDs we have no NVD data for (no --nvd, or lookup miss)
        # can't be classified and are kept as-is.
        dos_ids = {cid for cid in all_ids if nvd_by_id.get(cid, {}).get("dos_only")}
        cve_ids = all_ids - dos_ids
        if not cve_ids:
            continue
        # PoC-confirmed CVEs first — a working public exploit outranks raw
        # CVSS as a red-team signal — then by CVSS descending, unscored last.
        ranked = sorted(cve_ids, key=lambda cid: (
            0 if nvd_by_id.get(cid, {}).get("poc") else 1,
            -(nvd_by_id.get(cid, {}).get("cvss") if nvd_by_id.get(cid, {}).get("cvss") is not None else -1),
            cid))
        cvss_values = [nvd_by_id[cid]["cvss"] for cid in cve_ids
                       if nvd_by_id.get(cid, {}).get("cvss") is not None]
        max_cvss = max(cvss_values) if cvss_values else None
        poc_ids = [cid for cid in cve_ids if nvd_by_id.get(cid, {}).get("poc")]
        unscored = len(cve_ids) - len(cvss_values)

        severity = min(
            (_cve_severity(nvd_by_id.get(cid, {}).get("cvss"), has_poc=bool(nvd_by_id.get(cid, {}).get("poc")))
             for cid in cve_ids),
            key=lambda s: ENTRY_SEVERITY_ORDER.get(s, 9))

        cvss_note = f" (max CVSS {max_cvss})" if max_cvss is not None else ""
        poc_note = f" [{len(poc_ids)} with public PoC]" if poc_ids else ""
        dos_note = f" [{len(dos_ids)} DoS-only CVE(s) excluded]" if dos_ids else ""
        unscored_note = f" [{unscored} unscored — run --nvd for full data]" if unscored and not cvss_values else \
                         (f" [{unscored} unscored]" if unscored else "")
        # Cross-references the reported CPEs against the live tech-detect
        # probe (enrich.confirm_tech_stack) — Shodan/InternetDB data can be
        # weeks stale, so this flags whether the vulnerable software still
        # looks live, to cut down manual triage.
        tech_note = " [tech-stack confirmed live]" if h.tech_confirmed is True else \
                    (" [unconfirmed — live probe found no matching software, may be stale]"
                     if h.tech_confirmed is False else "")
        detail = "; ".join(
            cid + (f" (CVSS {nvd_by_id[cid]['cvss']})" if nvd_by_id.get(cid, {}).get("cvss") is not None else "")
            + (" [PoC]" if nvd_by_id.get(cid, {}).get("poc") else "")
            + (f" — {nvd_by_id[cid]['desc']}" if nvd_by_id.get(cid, {}).get("desc") else "")
            for cid in ranked[:known_cve_cap])
        if len(ranked) > known_cve_cap:
            detail += f"; +{len(ranked) - known_cve_cap} more"
        out.append({"type": "known-cve", "target": h.subdomain,
                   "severity": severity,
                   "summary": f"{len(ranked)} known CVE(s){cvss_note}{poc_note}{dos_note}"
                              f"{unscored_note}{tech_note}: {detail}",
                   "attck": "T1190"})

    # Non-web open ports — services lrecon's HTTP probe never touches, so
    # they need a manual look (RDP/SMB/VNC/WinRM/Telnet especially).
    for h in hosts:
        nwp = non_web_ports(h.ports)
        if not nwp:
            continue
        labeled = [f"{p} ({NON_WEB_PORT_INFO[p][0]})" if p in NON_WEB_PORT_INFO else str(p)
                  for p in nwp]
        sev = min((NON_WEB_PORT_INFO.get(p, (None, "medium"))[1] for p in nwp),
                 key=lambda s: ENTRY_SEVERITY_ORDER.get(s, 9))
        out.append({"type": "non-web-port", "target": h.subdomain, "severity": sev,
                   "summary": f"Non-web port(s) open, needs manual review: {', '.join(labeled)}",
                   "attck": "T1046"})

    for d, bs in (breach or {}).items():
        if bs:
            out.append({"type": "breach-exposure", "target": d, "severity": "medium",
                       "summary": f"{len(bs)} known breach(es) — password-spray candidate list",
                       "attck": "T1110.003"})

    if github_findings:
        repos = sorted({g["repo"] for g in github_findings if g.get("repo")})
        out.append({"type": "github-code-exposure",
                   "target": ", ".join(repos[:5]) + ("…" if len(repos) > 5 else ""),
                   "severity": "medium",
                   "summary": f"{len(github_findings)} public code hit(s) referencing scope across "
                              f"{len(repos)} repo(s) — review for leaked credentials",
                   "attck": "T1593.003"})

    # WHOIS / domain-registration checks — derived from data core.run() already
    # collected (res["whois"]), no extra network calls. Two signals:
    #   * a near-expiry or lapsed registration (operational risk to flag, and for
    #     a lapsed domain a re-registration/takeover vector), and
    #   * registrant PII disclosed with WHOIS privacy off (harvestable OSINT).
    for d, w in (whois or {}).items():
        if not w:
            continue
        days = _days_to_expiry(w.get("expires"))
        if days is not None and days <= 30:
            reg = f" (registrar: {w['registrar']})" if w.get("registrar") else ""
            if days < 0:
                out.append({"type": "whois-domain-expired", "target": d, "severity": "high",
                           "summary": f"Domain registration lapsed {abs(days)} day(s) ago "
                                      f"({w['expires']}){reg} — re-registration/takeover risk",
                           "attck": "T1590.001"})
            else:
                sev = "high" if days <= 7 else "medium"
                out.append({"type": "whois-domain-expiring", "target": d, "severity": sev,
                           "summary": f"Domain registration expires in {days} day(s) "
                                      f"({w['expires']}){reg} — flag to client",
                           "attck": "T1590.001"})

        if w.get("privacy_protected") is False:
            registrant = w.get("registrant_name") or w.get("registrant_org")
            if registrant:
                out.append({"type": "whois-registrant-exposed", "target": d, "severity": "info",
                           "summary": f"WHOIS privacy off — registrant disclosed ({registrant}); "
                                      f"harvestable identity/org OSINT",
                           "attck": "T1591"})

    out.sort(key=lambda e: ENTRY_SEVERITY_ORDER.get(e["severity"], 9))
    return out

