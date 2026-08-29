#!/usr/bin/env python3
"""
lrecon v2.2 — external attack-surface recon orchestrator for authorized pentests.

Phased pipeline (parallel within each phase):
  1. PASSIVE ENUM   crt.sh + certspotter + OTX + anubis + Wayback + Shodan DNS +
                    subfinder — all keyless except Shodan/subfinder. Per-source
                    attribution so you can SEE what each source contributed.
  2. RESOLUTION     shared fast resolver, A/AAAA/CNAME concurrent, wildcard filter
  3. ENRICHMENT     per UNIQUE IP: IPinfo (ASN/org/rDNS, always available) +
                    Shodan host / InternetDB (ports/CVEs, only if indexed)
  4. ACTIVE         optional TCP connect scan + HTTP probe + takeover checks

Enrichment note: Shodan/InternetDB only hold data for IPs they've scanned, so
they're often empty — that's expected. IPinfo fills ASN/org/rDNS regardless.

Key precedence (each): --<svc>-key  >  $<SVC>_API_KEY / $IPINFO_TOKEN  >  config
Config: ~/.config/lrecon/config.json  {"shodan_api_key":"...","ipinfo_token":"...",
  "github_token":"...", "hibp_api_key":"...", "hunter_api_key":"...",
  "rocketreach_api_key":"...", "google_cse_key":"...", "google_cse_cx":"...",
  "brave_search_key":"...", "vertex":{"access_token":"...","project":"...","engine":"..."},
  "vt_api_key":"..."}

ROE tiers: --passive-only | (default active) | --active-ports
ATT&CK: TA0043. Passive ~T1596/T1593. Active ~T1595/T1590. Takeover ~T1584.001.
Authorized engagement use only.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import random
import shutil
import string
import sys
import time
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

try:
    import dns.asyncresolver
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False

try:
    from rich.console import Console
    from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                               TimeElapsedColumn, MofNCompleteColumn)
    _HAVE_RICH = True
    _console = Console(stderr=True)
except Exception:
    _HAVE_RICH = False
    _console = None
    Progress = SpinnerColumn = BarColumn = TextColumn = None
    TimeElapsedColumn = MofNCompleteColumn = None


# What each line prefix means, and how it should read at a glance in a long run.
# Only the prefix is tinted: colouring whole lines would fight the highlighter
# that colours IPs, URLs and counts inside the message.
LOG_PREFIX_STYLES = {
    "[!]": "bold red",        # problem, failure, or a finding worth stopping at
    "[+]": "bold green",      # success / something was found
    "[i]": "dim",             # informational, safe to skim past
    "[-]": "yellow",          # negative result worth noticing
    "[*]": "bold cyan",       # in-progress / section marker
}


def log(msg: str) -> None:
    """Print a log line verbatim, coloured by severity.

    `markup=False` is load-bearing, not a style choice: rich parses square
    brackets as markup tags and *deletes* the ones it recognises. Every `[i]`
    prefix in the codebase was being eaten as an italic tag, and the cert-pass
    hint rendered as `pip install 'lrecon'` — an instruction that installs
    nothing, because `[tls]` disappeared. lrecon builds its own `[+]`/`[i]`
    prefixes and never uses rich markup here, so nothing is lost by disabling it.

    Highlighting is deliberately left ON. It was switched off alongside markup,
    which was a mistake: the two are independent, and it is highlighting — not
    markup — that colours IPs, URLs, counts and quoted strings, i.e. the thing
    that makes a finding stand out in a long run.

    On top of that, the prefix itself is styled by severity, so a red `[!]` is
    findable while scrolling without reading the text. The prefix is written as
    a separate styled span rather than via markup, precisely because markup is
    off — and the message keeps going through the highlighter unchanged, so the
    two colouring layers compose instead of competing.

    rich emits ANSI only when attached to a terminal and honours NO_COLOR, so
    this behaves the same under fish/bash/zsh and stays clean when piped.
    """
    if not _HAVE_RICH:
        print(msg, file=sys.stderr)
        return
    style = LOG_PREFIX_STYLES.get(msg[:3]) if len(msg) >= 3 else None
    if style:
        # end="" on the prefix so the two spans land on one line. The remainder
        # is printed normally, which keeps the highlighter working on it.
        _console.print(msg[:3], style=style, markup=False, highlight=False, end="")
        _console.print(msg[3:], markup=False)
    else:
        _console.print(msg, markup=False)


# names re-exported to sibling modules via `from .common import *`
__all__ = [
    "log", "Host", "Person", "RateLimiter", "load_keys",
    "CONFIG_PATH", "DEFAULT_RESOLVERS", "TOP_PORTS", "WEB_PORTS", "TAKEOVER_SIGS", "CF_FALLBACK",
    "SELF_SERVE", "ACCOUNT_BOUND", "NOT_CLAIMABLE", "TAKEOVER_ERROR_STATUSES",
    "non_web_ports", "human_bytes", "in_cf",
    "_HAVE_DNS", "_HAVE_RICH", "_console",
    "Progress", "SpinnerColumn", "BarColumn", "TextColumn",
    "TimeElapsedColumn", "MofNCompleteColumn",
    "httpx", "asyncio", "json", "defaultdict", "Path", "datetime", "timezone",
    "dataclass", "field", "asdict", "ipaddress",
]



# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
CONFIG_PATH = Path.home() / ".config" / "lrecon" / "config.json"
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
             465, 587, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985,
             6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9443, 27017]

# General-purpose HTTP(S) app/proxy ports — what lrecon's HTTP probe and
# tech-detect actually touch. Everything else in TOP_PORTS (or reported by
# Shodan/InternetDB/naabu outside it) is a non-HTTP service the probe never
# looks at, so it needs a human to go check it by hand.
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}


def in_cf(ip: str, nets) -> bool:
    """True if `ip` falls in any of `nets` (Cloudflare ranges as ip_network
    objects). Lives here rather than in intel.py because enrich.py needs it and
    can't import from intel (intel imports enrich)."""
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except Exception:
        return False


def human_bytes(n) -> str:
    """Byte count as a short human-readable string ("4.2 MB"). Returns "—" for
    None/unknown so report tables can use it directly."""
    if n is None:
        return "—"
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def non_web_ports(ports: list) -> list:
    """Open ports outside WEB_PORTS, sorted — the ones worth a manual look
    since the HTTP probe pipeline never touches them."""
    return sorted(p for p in ports if p not in WEB_PORTS)

# How a dangling target under each provider could actually be claimed. Broken and
# claimable are different questions, and only the second one is a takeover: an
# attacker who cannot recreate the name has nothing to take over, however dead
# the record is.
#
#   SELF_SERVE    — the exact target name is re-registrable by anyone. Bucket
#                   names, GitHub usernames, Heroku and Azure app names are all
#                   customer-chosen and globally unique, so releasing one puts it
#                   back in the pool. This is the classic takeover.
#   ACCOUNT_BOUND — the hostname is provider-assigned and cannot be recreated,
#                   but the *custom domain* pointed at it may be attachable to an
#                   attacker's own service, subject to whatever domain
#                   verification the provider does. A lead, never a confirmed
#                   takeover from DNS alone.
#   NOT_CLAIMABLE — the name carries a provider-generated random component and
#                   can never be asked for again. Stale DNS to clean up, not a
#                   takeover. Kept deliberately narrow: only names whose
#                   generated component we can point at.
SELF_SERVE, ACCOUNT_BOUND, NOT_CLAIMABLE = "self_serve", "account_bound", "not_claimable"

# HTTP statuses that make an unrecognised body worth a weak lead. A provider that
# has reworded its unclaimed-service page still errors; a 2xx serving ordinary
# content is a working site and evidence of nothing.
TAKEOVER_ERROR_STATUSES = {403, 404, 410, 503}

TAKEOVER_SIGS = {
    "s3.amazonaws.com":     (SELF_SERVE,    ["nosuchbucket", "the specified bucket does not exist"]),
    "github.io":            (SELF_SERVE,    ["there isn't a github pages site here"]),
    "herokuapp.com":        (SELF_SERVE,    ["no such app", "herokucdn.com/error-pages/no-such-app"]),
    "azurewebsites.net":    (SELF_SERVE,    ["404 web site not found", "error 404 - web app not found"]),
    "cloudapp.net":         (SELF_SERVE,    ["404 web site not found"]),
    "trafficmanager.net":   (SELF_SERVE,    ["404 web site not found"]),
    "wordpress.com":        (SELF_SERVE,    ["do you want to register"]),
    "pantheonsite.io":      (SELF_SERVE,    ["the gods are wise, but do not know of the site"]),
    "ghost.io":             (SELF_SERVE,    ["the thing you were looking for is no longer here"]),
    "readthedocs.io":       (SELF_SERVE,    ["unknown domain"]),
    "surge.sh":             (SELF_SERVE,    ["project not found"]),
    # d.sni.global.fastly.net is a shared endpoint every Fastly customer points
    # at — it is never per-customer and never disappears. Claiming means adding
    # the domain to your own Fastly service, which their verification governs.
    "fastly.net":           (ACCOUNT_BOUND, ["fastly error: unknown domain"]),
    # k8s-...-d961a91db8-1411441002.us-east-1.elb.amazonaws.com — the hash and
    # ID are AWS-assigned. Deleting the load balancer retires the name for good;
    # no one, including the account that owned it, can ask for it back.
    "elb.amazonaws.com":    (NOT_CLAIMABLE, []),
    # --- Common PaaS/SaaS providers (extends the table, not the logic) ---
    # First-come claimable subdomains: an unclaimed name is re-registrable by
    # anyone, so a dead CNAME here is a confirmed takeover.
    "gitlab.io":            (SELF_SERVE,    ["the page you're looking for could not be found"]),
    "web.app":              (SELF_SERVE,    ["site not found", "the specified bucket does not exist"]),
    "firebaseapp.com":      (SELF_SERVE,    ["site not found"]),
    "bitbucket.io":         (SELF_SERVE,    ["repository not found"]),
    "freshdesk.com":        (SELF_SERVE,    ["may have been moved or deleted"]),
    # Provider-assigned / domain-verified: the hostname is attachable only after
    # the provider's domain verification, so a dead CNAME here is "possible",
    # not confirmed (mark_dangling_cname keeps it at that confidence).
    "netlify.app":          (ACCOUNT_BOUND, ["not found - request id"]),
    "vercel.app":           (ACCOUNT_BOUND, ["the deployment could not be found", "404: not_found"]),
    "myshopify.com":        (ACCOUNT_BOUND, ["sorry, this shop is currently unavailable"]),
    "statuspage.io":        (ACCOUNT_BOUND, []),
}

# Cloudflare published ranges (fallback if live fetch fails)
CF_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]



# --------------------------------------------------------------------------- #
# Config / API keys
# --------------------------------------------------------------------------- #
def _resolve_vertex(cfg_base, args) -> dict | None:
    """Merge Vertex AI Search settings from config.json (`cfg_base`), env vars,
    and CLI flags — per field, precedence config < env < CLI. Returns None when
    nothing at all is configured so callers can treat Vertex as absent."""
    base = dict(cfg_base) if isinstance(cfg_base, dict) else {}
    env = {
        "access_token": os.environ.get("VERTEX_ACCESS_TOKEN") or os.environ.get("GOOGLE_ACCESS_TOKEN"),
        "project": os.environ.get("VERTEX_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT"),
        "location": os.environ.get("VERTEX_LOCATION"),
        "engine": os.environ.get("VERTEX_ENGINE"),
        "datastore": os.environ.get("VERTEX_DATASTORE"),
    }
    cli = {
        "access_token": getattr(args, "vertex_access_token", None),
        "project": getattr(args, "vertex_project", None),
        "location": getattr(args, "vertex_location", None),
        "engine": getattr(args, "vertex_engine", None),
        "datastore": getattr(args, "vertex_datastore", None),
    }
    out = dict(base)
    for field in ("access_token", "project", "location", "engine", "datastore"):
        if env.get(field):
            out[field] = env[field]
        if cli.get(field):
            out[field] = cli[field]
    if not any(out.get(f) for f in ("access_token", "project", "engine", "datastore")):
        return None
    out.setdefault("location", "global")
    return out


def load_keys(args) -> dict:
    keys = {"shodan": None, "ipinfo": None, "github": None, "hibp": None,
            "hunter": None, "rocketreach": None, "google_cse": None, "google_cse_cx": None,
            # Search-engine dork backends (Google CSE is closed to new
            # customers; brave/vertex are the replacement backends). `vertex`
            # is a dict: access_token/project/location/engine/datastore.
            "brave": None, "vertex": None,
            "vt": None, "otx": None,
            # LLM (dossier/news synthesis): cloud-provider keys + the resolved
            # `llm` config section (provider/model/base_url/... from config.json).
            "openai": None, "anthropic": None, "google_ai": None, "llm": None}
    cfg = Path(args.config) if args.config else CONFIG_PATH
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text())
            keys["shodan"] = data.get("shodan_api_key")
            keys["ipinfo"] = data.get("ipinfo_token")
            keys["github"] = data.get("github_token")
            keys["hibp"] = data.get("hibp_api_key")
            keys["hunter"] = data.get("hunter_api_key")
            keys["rocketreach"] = data.get("rocketreach_api_key")
            keys["google_cse"] = data.get("google_cse_key")
            keys["google_cse_cx"] = data.get("google_cse_cx")
            keys["brave"] = data.get("brave_search_key")
            keys["vertex"] = data.get("vertex") if isinstance(data.get("vertex"), dict) else None
            keys["vt"] = data.get("vt_api_key")
            keys["otx"] = data.get("otx_api_key")
            keys["openai"] = data.get("openai_api_key")
            keys["anthropic"] = data.get("anthropic_api_key")
            keys["google_ai"] = data.get("google_ai_api_key")
            keys["llm"] = data.get("llm")            # {"provider":..., "model":..., ...}
        except Exception as e:
            log(f"[!] config read failed: {e}")
    keys["shodan"] = os.environ.get("SHODAN_API_KEY") or keys["shodan"]
    keys["ipinfo"] = os.environ.get("IPINFO_TOKEN") or keys["ipinfo"]
    keys["github"] = os.environ.get("GITHUB_TOKEN") or keys["github"]
    keys["hibp"] = os.environ.get("HIBP_API_KEY") or keys["hibp"]
    keys["hunter"] = os.environ.get("HUNTER_API_KEY") or keys["hunter"]
    keys["rocketreach"] = os.environ.get("ROCKETREACH_API_KEY") or keys["rocketreach"]
    keys["google_cse"] = os.environ.get("GOOGLE_CSE_KEY") or keys["google_cse"]
    keys["google_cse_cx"] = os.environ.get("GOOGLE_CSE_CX") or keys["google_cse_cx"]
    keys["brave"] = os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("BRAVE_API_KEY") \
        or keys["brave"]
    keys["vertex"] = _resolve_vertex(keys["vertex"], args)
    keys["vt"] = os.environ.get("VT_API_KEY") or keys["vt"]
    keys["otx"] = os.environ.get("OTX_API_KEY") or keys["otx"]
    keys["openai"] = os.environ.get("OPENAI_API_KEY") or keys["openai"]
    keys["anthropic"] = os.environ.get("ANTHROPIC_API_KEY") or keys["anthropic"]
    keys["google_ai"] = os.environ.get("GOOGLE_AI_API_KEY") or keys["google_ai"]
    if args.shodan_key:
        keys["shodan"] = args.shodan_key
    if args.ipinfo_key:
        keys["ipinfo"] = args.ipinfo_key
    if args.hunter_key:
        keys["hunter"] = args.hunter_key
    if args.rocketreach_key:
        keys["rocketreach"] = args.rocketreach_key
    if args.google_cse_key:
        keys["google_cse"] = args.google_cse_key
    if args.google_cse_cx:
        keys["google_cse_cx"] = args.google_cse_cx
    if getattr(args, "brave_key", None):
        keys["brave"] = args.brave_key
    if args.vt_key:
        keys["vt"] = args.vt_key
    if getattr(args, "otx_key", None):
        keys["otx"] = args.otx_key
    # LLM CLI overrides layer on top of the config.json `llm` section.
    llm_over = {k: v for k, v in (
        ("provider", getattr(args, "llm_provider", None)),
        ("model", getattr(args, "llm_model", None)),
        ("base_url", getattr(args, "llm_base_url", None)),
    ) if v}
    if llm_over:
        keys["llm"] = {**(keys["llm"] or {}), **llm_over}
    if args.ask_keys:
        import getpass
        if not keys["shodan"]:
            keys["shodan"] = getpass.getpass("Shodan API key (blank to skip): ").strip() or None
        if not keys["ipinfo"]:
            keys["ipinfo"] = getpass.getpass("IPinfo token (blank to skip): ").strip() or None
    return keys



# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, per_second: float):
        self.min_interval = 1.0 / per_second
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self):
        async with self.lock:
            loop = asyncio.get_event_loop()
            delta = loop.time() - self.last
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self.last = loop.time()



# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Host:
    subdomain: str
    ips: list = field(default_factory=list)
    cname: str | None = None
    ports: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    ip_asn: dict = field(default_factory=dict)   # {ip: "ASxxxxx"} — asn above is last-IP-wins
    ip_org: dict = field(default_factory=dict)   # {ip: "Org Name"} — parallel to ip_asn
    ip_country: dict = field(default_factory=dict)  # {ip: "US"} — parallel to ip_asn/ip_org
    rdns: str | None = None
    # First IP wins, so a host whose addresses span regions shows only one of
    # them. Kept for existing consumers; ip_country above is the honest view.
    country: str | None = None
    http_status: int | None = None
    http_title: str | None = None
    server: str | None = None
    powered_by: str | None = None
    tech: list = field(default_factory=list)
    scheme: str | None = None
    final_url: str | None = None
    favicon_hash: int | None = None
    # Live-verified paths on this host: [{path, status, source}]. Populated by
    # the Wayback stale-endpoint hunt (source="wayback") and, later, API-doc/JS
    # discovery. An "interesting" status on a sensitive path becomes an entry
    # point via summarize_entry_points.
    endpoints: list = field(default_factory=list)
    # Secret leads found in this host's same-origin JS bundles:
    # [{kind, url, masked}] — never the full secret. Leads, not confirmations;
    # each becomes a (verify-me) entry point via summarize_entry_points.
    js_secrets: list = field(default_factory=list)
    # Service banners grabbed on open ports: [{port, service, banner}] (SSH
    # ident, TLS cert summary, generic first line). An SSH version also feeds
    # host.tech for CVE tech-confirmation.
    banners: list = field(default_factory=list)
    # HTTP security posture of the response: CSP/HSTS/X-Frame-Options/etc. and
    # per-cookie Secure/HttpOnly/SameSite flags (see headers.security_headers).
    sec_headers: dict = field(default_factory=dict)
    # CDN/WAF fronting the host, from response headers (Cloudflare, Akamai,
    # Fastly, CloudFront, Imperva, Sucuri) — see waf.fingerprint_waf.
    waf: str | None = None
    # Analytics/marketing IDs on the page ({ga/gtm/fb: [ids]}) — an ownership
    # fingerprint; hosts sharing one are the same team's (see pixels.py).
    tracking_ids: dict = field(default_factory=dict)
    nvd_cves: list = field(default_factory=list)
    tech_confirmed: bool | None = None    # None=no live tech data to check; see enrich.confirm_tech_stack
    takeover: str | None = None
    # "confirmed" (CNAME target is NXDOMAIN), "likely" (provider's unclaimed
    # signature matched in the body) or "possible" (CNAME points at a known
    # takeover-prone provider, nothing corroborated). Drives entry-point
    # severity — a phrase-match on `takeover` used to stand in for this.
    takeover_confidence: str | None = None
    # A dead CNAME whose target provably cannot be reclaimed (see NOT_CLAIMABLE).
    # Deliberately not a takeover: the remedy is deleting the record, not racing
    # an attacker, and filing it as a takeover lead sends someone chasing a name
    # that cannot be registered.
    stale_dns: str | None = None
    # A delegated nameserver for this zone that no longer resolves — whoever can
    # register the NS name controls the zone's DNS (a zone-level takeover).
    ns_takeover: str | None = None
    wildcard: bool = False
    # Set only when resolution definitively returned NXDOMAIN — the name does not
    # exist. Deliberately distinct from "no IPs": a timeout or SERVFAIL also
    # yields no IPs but is inconclusive, and must not be treated as dead (e.g. on
    # the client scope sheet). Never set on the dnsx path, which can't tell an
    # absent host from a non-existent one.
    nxdomain: bool = False
    enrich_src: set = field(default_factory=set)
    source: set = field(default_factory=set)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = sorted(self.source)
        d["enrich_src"] = sorted(self.enrich_src)
        return d


@dataclass
class Person:
    """
    One company-affiliated person discovered via OSINT — deliberately just
    professional/company data (name, title, company email), never personal
    accounts/contact info, matching the intended use as a red-team phishing/
    password-spray candidate list, not a broader people-search result.
    """
    email: str
    name: str | None = None
    position: str | None = None
    confidence: int | None = None        # 0-100 where the source provides one (e.g. Hunter)
    generated: bool = False              # True if pattern-generated, not directly observed
    smtp_status: str | None = None       # "valid" | "invalid" | "catch-all" | "unknown" | None
    source: set = field(default_factory=set)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = sorted(self.source)
        return d


