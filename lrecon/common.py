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
  "rocketreach_api_key":"...", "google_cse_key":"...", "google_cse_cx":"..."}

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


def log(msg: str) -> None:
    if _HAVE_RICH:
        _console.print(msg)
    else:
        print(msg, file=sys.stderr)


# names re-exported to sibling modules via `from .common import *`
__all__ = [
    "log", "Host", "Person", "RateLimiter", "load_keys",
    "CONFIG_PATH", "DEFAULT_RESOLVERS", "TOP_PORTS", "TAKEOVER_SIGS", "CF_FALLBACK",
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

TAKEOVER_SIGS = {
    "s3.amazonaws.com":     ["nosuchbucket", "the specified bucket does not exist"],
    "github.io":            ["there isn't a github pages site here"],
    "herokuapp.com":        ["no such app", "herokucdn.com/error-pages/no-such-app"],
    "azurewebsites.net":    ["404 web site not found", "error 404 - web app not found"],
    "cloudapp.net":         ["404 web site not found"],
    "trafficmanager.net":   ["404 web site not found"],
    "wordpress.com":        ["do you want to register"],
    "pantheonsite.io":      ["the gods are wise, but do not know of the site"],
    "fastly.net":           ["fastly error: unknown domain"],
    "ghost.io":             ["the thing you were looking for is no longer here"],
    "readthedocs.io":       ["unknown domain"],
    "surge.sh":             ["project not found"],
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
def load_keys(args) -> dict:
    keys = {"shodan": None, "ipinfo": None, "github": None, "hibp": None,
            "hunter": None, "rocketreach": None, "google_cse": None, "google_cse_cx": None}
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
    rdns: str | None = None
    country: str | None = None
    http_status: int | None = None
    http_title: str | None = None
    server: str | None = None
    powered_by: str | None = None
    tech: list = field(default_factory=list)
    scheme: str | None = None
    final_url: str | None = None
    favicon_hash: int | None = None
    nvd_cves: list = field(default_factory=list)
    tech_confirmed: bool | None = None    # None=no live tech data to check; see enrich.confirm_tech_stack
    takeover: str | None = None
    wildcard: bool = False
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


