"""Unit tests for LRecon pure-logic and backend parsers (no network required)."""
import argparse
import csv
import ipaddress
import sys
import tempfile
from pathlib import Path

import pytest

import lrecon
from lrecon import enrich, intel, state, backends, sources, report, people, cli, core, dorking, vt
from lrecon.common import Host, Person, CF_FALLBACK, WEB_PORTS, non_web_ports


# --------------------------------------------------------------------------- #
# Enrichment logic
# --------------------------------------------------------------------------- #
def test_cpe22_to_23_conversion():
    assert enrich._cpe23("cpe:/a:nginx:nginx:1.18.0") == \
        "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    # already-2.3 passes through untouched
    v = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert enrich._cpe23(v) == v


def test_favicon_hash_is_deterministic_int():
    a = enrich._favicon_mmh3(b"favicon-bytes")
    b = enrich._favicon_mmh3(b"favicon-bytes")
    assert a == b and isinstance(a, int)


def test_apply_ipinfo_parses_asn_and_org():
    h = Host("a.x.com")
    enrich.apply_ipinfo(h, {"org": "AS15169 Google LLC", "hostname": "a.x.com",
                            "country": "US"})
    assert h.asn == "AS15169"
    assert h.org == "Google LLC"
    assert h.rdns == "a.x.com"
    assert h.country == "US"
    assert h.ip_asn == {}                        # no ip passed -> per-IP map untouched
    assert h.ip_org == {}


def test_apply_ipinfo_records_per_ip_asn_for_multi_ip_hosts():
    h = Host("a.x.com", ips=["1.2.3.4", "5.6.7.8"])
    enrich.apply_ipinfo(h, {"org": "AS15169 Google LLC"}, "1.2.3.4")
    enrich.apply_ipinfo(h, {"org": "AS13335 Cloudflare"}, "5.6.7.8")
    assert h.ip_asn == {"1.2.3.4": "AS15169", "5.6.7.8": "AS13335"}
    assert h.ip_org == {"1.2.3.4": "Google LLC", "5.6.7.8": "Cloudflare"}
    assert h.asn == "AS13335"                    # scalar field: still last-IP-wins


def test_apply_ipinfo_records_per_ip_org_without_asn_prefix():
    # org string without a leading "ASxxxxx" token — still worth recording
    # per-IP, just with no ASN to go with it.
    h = Host("a.x.com", ips=["1.2.3.4"])
    enrich.apply_ipinfo(h, {"org": "Some Hosting Co"}, "1.2.3.4")
    assert h.ip_org == {"1.2.3.4": "Some Hosting Co"}
    assert h.ip_asn == {}
    assert h.org == "Some Hosting Co"


def test_non_web_ports_filters_out_web_ports():
    assert non_web_ports([80, 443, 8080]) == []
    assert non_web_ports([80, 22, 3389, 443]) == [22, 3389]
    assert non_web_ports([]) == []


def test_non_web_ports_keeps_elasticsearch_flagged():
    # 9200 speaks HTTP but is a database service worth flagging, not a
    # general-purpose web/app-proxy port.
    assert 9200 not in WEB_PORTS
    assert non_web_ports([9200]) == [9200]


async def test_enrich_ipinfo_omits_token_param_when_keyless():
    # IPinfo's /json endpoint works without a token (lower, unauthenticated
    # rate limit) — this is the capability the whole "ASN/org shouldn't be
    # gated behind a configured key" fix relies on.
    async def fake_get(url, timeout=None):
        assert url == "https://ipinfo.io/8.8.8.8/json"
        assert "token" not in url
        return _FakeResp(200, {"org": "AS15169 Google LLC"})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await enrich.enrich_ipinfo(client, "8.8.8.8", None)
    assert out["org"] == "AS15169 Google LLC"


async def test_enrich_ipinfo_includes_token_param_when_configured():
    async def fake_get(url, timeout=None):
        assert url == "https://ipinfo.io/8.8.8.8/json?token=abc123"
        return _FakeResp(200, {"org": "AS15169 Google LLC"})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await enrich.enrich_ipinfo(client, "8.8.8.8", "abc123")
    assert out["org"] == "AS15169 Google LLC"


def test_apply_ports_merges_and_tags_source():
    h = Host("a.x.com", ports=[80])
    enrich.apply_ports(h, {"ports": [443, 80], "vulns": ["CVE-2026-1"]}, "internetdb")
    assert h.ports == [80, 443]
    assert h.vulns == ["CVE-2026-1"]
    assert "internetdb" in h.enrich_src


# --------------------------------------------------------------------------- #
# Tech-stack confirmation (live probe vs. Shodan/InternetDB CPEs)
# --------------------------------------------------------------------------- #
def test_cpe_vendor_product_extracts_from_cpe23():
    assert enrich._cpe_vendor_product("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") == \
        ("apache", "http server")


def test_cpe_vendor_product_extracts_from_cpe22():
    assert enrich._cpe_vendor_product("cpe:/a:wordpress:wordpress:6.4.2") == \
        ("wordpress", "wordpress")


def test_cpe_vendor_product_handles_wildcards_and_short_strings():
    assert enrich._cpe_vendor_product("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*") == (None, None)
    assert enrich._cpe_vendor_product("cpe:2.3:a") == (None, None)


def test_tech_stack_confirms_cpe_matches_product_name():
    assert enrich.tech_stack_confirms_cpe(["WordPress:6.4.2"],
                                          "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*") is True
    assert enrich.tech_stack_confirms_cpe(["nginx"],
                                          "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") is False


def test_tech_stack_confirms_cpe_matches_underscore_normalized_product():
    # "http_server" (CPE) vs "Apache" (live tech) — vendor match via substring
    assert enrich.tech_stack_confirms_cpe(["Apache:2.4.49"],
                                          "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") is True


def test_tech_stack_confirms_cpe_false_when_no_tech_data():
    assert enrich.tech_stack_confirms_cpe([], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") is False


def test_confirm_tech_stack_true_when_a_cpe_matches():
    h = Host("a.x.com", cpes=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"], tech=["Apache:2.4.49"])
    assert enrich.confirm_tech_stack(h) is True


def test_confirm_tech_stack_false_when_no_cpe_matches():
    h = Host("a.x.com", cpes=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"], tech=["nginx"])
    assert enrich.confirm_tech_stack(h) is False


def test_confirm_tech_stack_none_when_no_live_tech_or_no_cpes():
    assert enrich.confirm_tech_stack(Host("a.x.com", cpes=["cpe:2.3:a:x:y:1:*"], tech=[])) is None
    assert enrich.confirm_tech_stack(Host("a.x.com", cpes=[], tech=["nginx"])) is None


# --------------------------------------------------------------------------- #
# Passive enum: crt.sh retry/backoff hardening
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data
        self.content = b"1" if data is not None else b""

    def json(self):
        return self._data


class _FlakyClient:
    """Replays canned responses/exceptions in order; counts calls."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def get(self, url, timeout=None):
        self.calls += 1
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


async def test_enum_crtsh_retries_non_200_then_succeeds_and_includes_common_name(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)
    client = _FlakyClient([
        _FakeResp(429),
        _FakeResp(200, [{"name_value": "a.x.com\nb.x.com", "common_name": "c.x.com"}]),
    ])
    out = await sources.enum_crtsh(client, "x.com")
    assert out == {"a.x.com", "b.x.com", "c.x.com"}
    assert client.calls == 2


async def test_enum_crtsh_gives_up_after_max_attempts(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)
    client = _FlakyClient([_FakeResp(503)] * 4)
    out = await sources.enum_crtsh(client, "x.com")
    assert out == set()
    assert client.calls == 4


# --------------------------------------------------------------------------- #
# crt.sh direct-Postgres fallback (bypasses the flaky HTTP frontend entirely)
# --------------------------------------------------------------------------- #
async def test_crtsh_psql_parses_rows(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=900):
        return "a.x.com\nb.x.com\n"
    monkeypatch.setattr(backends, "_run", fake_run)
    rows = await backends.crtsh_psql("x.com")
    assert rows == ["a.x.com", "b.x.com"]


async def test_crtsh_psql_not_on_path_returns_none(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: False)
    assert await backends.crtsh_psql("x.com") is None


async def test_crtsh_psql_empty_output_returns_none(monkeypatch):
    # Covers both a genuinely empty result and a silent connection failure —
    # either way the caller falls back to the HTTP path as cheap insurance.
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=900):
        return ""
    monkeypatch.setattr(backends, "_run", fake_run)
    assert await backends.crtsh_psql("x.com") is None


async def test_enum_crtsh_best_uses_psql_when_it_succeeds(monkeypatch):
    async def fake_psql(domain):
        return ["a.x.com", "*.b.x.com", "unrelated.example.com"]
    monkeypatch.setattr(backends, "crtsh_psql", fake_psql)
    async def fail_if_called(client, domain):
        raise AssertionError("must not fall back to HTTP when psql already succeeded")
    monkeypatch.setattr(sources, "enum_crtsh", fail_if_called)
    out = await sources.enum_crtsh_best(None, "x.com")
    assert out == {"a.x.com", "b.x.com"}


async def test_enum_crtsh_best_falls_back_to_http_when_psql_unavailable(monkeypatch):
    async def fake_psql(domain):
        return None
    monkeypatch.setattr(backends, "crtsh_psql", fake_psql)
    async def fake_http(client, domain):
        return {"c.x.com"}
    monkeypatch.setattr(sources, "enum_crtsh", fake_http)
    out = await sources.enum_crtsh_best(None, "x.com")
    assert out == {"c.x.com"}


async def test_enum_crtsh_best_no_pd_skips_psql_entirely(monkeypatch):
    async def fail_if_called(domain):
        raise AssertionError("psql must not be tried when use_psql=False (--no-pd)")
    monkeypatch.setattr(backends, "crtsh_psql", fail_if_called)
    async def fake_http(client, domain):
        return {"d.x.com"}
    monkeypatch.setattr(sources, "enum_crtsh", fake_http)
    out = await sources.enum_crtsh_best(None, "x.com", use_psql=False)
    assert out == {"d.x.com"}


def test_parse_nvd_vuln_extracts_cvss_vector_desc_and_dos_flag():
    v = {"cve": {"id": "CVE-2026-1",
                 "descriptions": [{"lang": "en", "value": "Auth bypass allows remote code execution."}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {
                     "baseScore": 9.8,
                     "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}
    parsed = enrich._parse_nvd_vuln(v)
    assert parsed["id"] == "CVE-2026-1"
    assert parsed["cvss"] == 9.8
    assert parsed["dos_only"] is False
    assert "Auth bypass" in parsed["desc"]


def test_parse_nvd_vuln_flags_availability_only_impact_as_dos():
    v = {"cve": {"id": "CVE-2026-2", "descriptions": [],
                 "metrics": {"cvssMetricV31": [{"cvssData": {
                     "baseScore": 7.5,
                     "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]}}}
    parsed = enrich._parse_nvd_vuln(v)
    assert parsed["dos_only"] is True


def test_is_dos_only_handles_v2_vectors_and_missing_vector():
    assert enrich._is_dos_only("AV:N/AC:L/Au:N/C:N/I:N/A:C") is True     # CVSS v2 DoS-only
    assert enrich._is_dos_only("AV:N/AC:L/Au:N/C:C/I:C/A:C") is False    # v2, also confidentiality/integrity
    assert enrich._is_dos_only(None) is False                           # no vector data -> can't classify


async def test_poc_lookup_parses_and_sorts_by_stars(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(enrich.asyncio, "sleep", no_sleep)
    client = _FlakyClient([_FakeResp(200, [
        {"html_url": "https://github.com/a/low-stars", "stargazers_count": 2},
        {"html_url": "https://github.com/b/high-stars", "stargazers_count": 50},
    ])])
    limiter = enrich.RateLimiter(per_second=1000)
    out = await enrich.poc_lookup(client, "CVE-2024-1234", {}, limiter)
    assert [p["url"] for p in out] == [
        "https://github.com/b/high-stars", "https://github.com/a/low-stars"]


async def test_poc_lookup_404_means_no_poc_and_caches():
    client = _FlakyClient([_FakeResp(404)])
    cache = {}
    limiter = enrich.RateLimiter(per_second=1000)
    out = await enrich.poc_lookup(client, "CVE-2024-9999", cache, limiter)
    assert out == []
    assert cache["CVE-2024-9999"] == []
    assert client.calls == 1
    # second call hits the cache, no further request
    out2 = await enrich.poc_lookup(client, "CVE-2024-9999", cache, limiter)
    assert out2 == []
    assert client.calls == 1


async def test_poc_lookup_transient_failures_retried_not_cached_as_no_poc(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(enrich.asyncio, "sleep", no_sleep)
    client = _FlakyClient([_FakeResp(429), _FakeResp(503), _FakeResp(500)])
    cache = {}
    limiter = enrich.RateLimiter(per_second=1000)
    out = await enrich.poc_lookup(client, "CVE-2024-5555", cache, limiter)
    assert out is None                            # unresolved, not a confirmed absence
    assert "CVE-2024-5555" not in cache           # must not be cached as a false negative
    assert client.calls == 3                      # exhausted all 3 attempts


async def test_poc_lookup_recovers_after_a_transient_failure(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(enrich.asyncio, "sleep", no_sleep)
    client = _FlakyClient([
        _FakeResp(429),
        _FakeResp(200, [{"html_url": "https://github.com/a/poc", "stargazers_count": 1}]),
    ])
    cache = {}
    limiter = enrich.RateLimiter(per_second=1000)
    out = await enrich.poc_lookup(client, "CVE-2024-6666", cache, limiter)
    assert out == [{"url": "https://github.com/a/poc", "stars": 1}]
    assert cache["CVE-2024-6666"] == out


def test_cve_severity_poc_floors_medium_and_low_to_high():
    assert intel._cve_severity(3.1, has_poc=True) == "high"     # low -> high
    assert intel._cve_severity(5.0, has_poc=True) == "high"     # medium -> high
    assert intel._cve_severity(9.8, has_poc=True) == "critical"  # already above high -> unchanged
    assert intel._cve_severity(3.1, has_poc=False) == "low"     # no poc -> unaffected


def test_summarize_entry_points_poc_confirmed_cve_ranks_ahead_of_higher_cvss():
    h = Host("legacy.x.com", nvd_cves=[
        {"id": "CVE-2024-HIGH", "cvss": 8.8, "desc": "High CVSS, no known exploit"},
        {"id": "CVE-2024-POC", "cvss": 4.5, "desc": "Medium CVSS but has a public PoC",
         "poc": [{"url": "https://github.com/x/poc", "stars": 10}]},
    ])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    summary = eps[0]["summary"]
    # PoC-confirmed CVE (lower CVSS) still sorts ahead of the higher-CVSS one.
    assert summary.index("CVE-2024-POC") < summary.index("CVE-2024-HIGH")
    assert "1 with public PoC" in summary
    assert "[PoC]" in summary


def test_summarize_entry_points_poc_bump_raises_aggregate_severity():
    # Both CVEs are medium-tier on raw CVSS alone (neither reaches the 7.0
    # "high" threshold); the PoC bump should raise the host's overall severity
    # to "high" even though max_cvss stays in medium range.
    h = Host("legacy.x.com", nvd_cves=[
        {"id": "CVE-2024-A", "cvss": 5.0, "desc": "Medium, no PoC"},
        {"id": "CVE-2024-B", "cvss": 4.5, "desc": "Medium but has a public PoC",
         "poc": [{"url": "https://github.com/x/poc", "stars": 3}]},
    ])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert eps[0]["severity"] == "high"


# --------------------------------------------------------------------------- #
# Intel: buckets + Cloudflare
# --------------------------------------------------------------------------- #
def test_bucket_candidates_permutation():
    c = intel.bucket_candidates(["acme"])
    assert "acme" in c and "acme-backups" in c
    assert all(" " not in name for name in c)          # valid bucket names


def test_in_cf_range_membership():
    nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    assert intel.in_cf("104.16.5.5", nets) is True      # Cloudflare edge
    assert intel.in_cf("8.8.8.8", nets) is False        # Google DNS


# --------------------------------------------------------------------------- #
# Domain registration (WHOIS via RDAP)
# --------------------------------------------------------------------------- #
_EXAMPLE_COM_RDAP = {
    "status": ["client delete prohibited", "client transfer prohibited"],
    "entities": [{"roles": ["registrar"],
                 "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                          ["fn", {}, "text", "RESERVED-IANA"]]]}],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
              {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
              {"eventAction": "last changed", "eventDate": "2026-01-16T18:26:50Z"}],
    "nameservers": [{"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"}, {"ldhName": "HERA.NS.CLOUDFLARE.COM"}],
}


def test_parse_rdap_extracts_registrar_dates_nameservers_status():
    out = intel._parse_rdap(_EXAMPLE_COM_RDAP)
    assert out["registrar"] == "RESERVED-IANA"
    assert out["created"] == "1995-08-14T04:00:00Z"
    assert out["expires"] == "2026-08-13T04:00:00Z"
    assert out["last_changed"] == "2026-01-16T18:26:50Z"
    assert out["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    assert len(out["status"]) == 2


def test_parse_rdap_handles_missing_fields_gracefully():
    out = intel._parse_rdap({})
    assert out == {"registrar": None, "created": None, "expires": None,
                   "last_changed": None, "nameservers": [], "status": [],
                   "registrant_name": None, "registrant_org": None,
                   "privacy_protected": None, "privacy_provider": None}


def test_rdap_entity_name_returns_none_when_no_fn_field():
    assert intel._rdap_entity_name({"vcardArray": ["vcard", [["version", {}, "text", "4.0"]]]}) is None
    assert intel._rdap_entity_name({}) is None


def test_parse_rdap_no_registrant_entity_leaves_privacy_unknown():
    # thin-registry response (e.g. registry-level .com via Verisign) — no
    # registrant entity at all, distinct from "confirmed not protected"
    out = intel._parse_rdap(_EXAMPLE_COM_RDAP)
    assert out["registrant_name"] is None
    assert out["privacy_protected"] is None


def test_parse_rdap_detects_privacy_via_redacted_conformance_extension():
    data = {
        "rdapConformance": ["rdap_level_0", "redacted"],
        "entities": [{"roles": ["registrant"],
                     "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                              ["fn", {}, "text", ""],
                                              ["org", {}, "text",
                                               "Privacy service provided by Withheld for Privacy ehf"]]]}],
    }
    out = intel._parse_rdap(data)
    assert out["privacy_protected"] is True
    assert out["privacy_provider"] == "Privacy service provided by Withheld for Privacy ehf"


def test_parse_rdap_detects_privacy_via_org_keyword_without_conformance_flag():
    data = {"entities": [{"roles": ["registrant"],
                         "vcardArray": ["vcard", [["fn", {}, "text", "Domain Admin"],
                                                  ["org", {}, "text", "WhoisGuard Protected"]]]}]}
    out = intel._parse_rdap(data)
    assert out["privacy_protected"] is True
    assert out["privacy_provider"] == "WhoisGuard Protected"


def test_parse_rdap_real_disclosed_registrant_not_flagged_private():
    data = {"entities": [{"roles": ["registrant"],
                         "vcardArray": ["vcard", [["fn", {}, "text", "Jane Doe"],
                                                  ["org", {}, "text", "Acme Corp"]]]}]}
    out = intel._parse_rdap(data)
    assert out["privacy_protected"] is False
    assert out["registrant_name"] == "Jane Doe"
    assert out["registrant_org"] == "Acme Corp"
    assert out["privacy_provider"] is None


def test_rdap_referral_link_finds_related_rdap_url():
    data = {"links": [{"rel": "self", "type": "application/rdap+json", "href": "https://registry/x"},
                      {"rel": "related", "type": "application/rdap+json", "href": "https://registrar/x"}]}
    assert intel._rdap_referral_link(data) == "https://registrar/x"
    assert intel._rdap_referral_link({}) is None


async def test_rdap_lookup_follows_registrar_referral_when_registry_has_no_registrant():
    registry_resp = {**_EXAMPLE_COM_RDAP,
                     "links": [{"rel": "related", "type": "application/rdap+json",
                                "href": "https://rdap.registrar.example/domain/x.com"}]}
    registrar_resp = {
        "rdapConformance": ["redacted"],
        "entities": [{"roles": ["registrant"],
                     "vcardArray": ["vcard", [["fn", {}, "text", ""],
                                              ["org", {}, "text", "Privacy service"]]]}],
    }
    calls = []

    async def fake_get(url, timeout=None, follow_redirects=None):
        calls.append(url)
        if "registrar.example" in url:
            return _FakeResp(200, registrar_resp)
        return _FakeResp(200, registry_resp)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await intel.rdap_lookup(client, "x.com")
    assert len(calls) == 2                                # followed the referral
    assert out["registrar"] == "RESERVED-IANA"            # kept from the registry response
    assert out["privacy_protected"] is True                # filled in from the referral
    assert out["privacy_provider"] == "Privacy service"


async def test_rdap_lookup_no_referral_link_skips_second_hop():
    async def fake_get(url, timeout=None, follow_redirects=None):
        return _FakeResp(200, _EXAMPLE_COM_RDAP)          # no "links" -> no referral
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await intel.rdap_lookup(client, "example.com")
    assert out["privacy_protected"] is None


def test_domain_expiring_soon():
    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    far = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    assert intel.domain_expiring_soon(soon) is True
    assert intel.domain_expiring_soon(far) is False
    assert intel.domain_expiring_soon(None) is False
    assert intel.domain_expiring_soon("not-a-date") is False


async def test_rdap_lookup_returns_empty_dict_on_404(monkeypatch):
    async def fake_get(url, timeout=None, follow_redirects=None):
        return _FakeResp(404)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await intel.rdap_lookup(client, "nonexistent-domain-xyz.test")
    assert out == {}


async def test_rdap_lookup_parses_200_response():
    async def fake_get(url, timeout=None, follow_redirects=None):
        assert follow_redirects is True   # rdap.org redirects to the authoritative registry
        return _FakeResp(200, _EXAMPLE_COM_RDAP)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await intel.rdap_lookup(client, "example.com")
    assert out["registrar"] == "RESERVED-IANA"


# --------------------------------------------------------------------------- #
# DNS records + mail infrastructure identification
# --------------------------------------------------------------------------- #
class _FakeMXRecord:
    def __init__(self, host, preference=10):
        self.exchange = host + "."
        self.preference = preference


class _FakeTXTRecord:
    def __init__(self, text):
        self.strings = [text.encode()]


class _FakeSOARecord:
    def __init__(self, mname):
        self.mname = mname + "."


class _FakeDNSResolver:
    """Generic fake resolver keyed by (name, rtype); raises (like a real
    NXDOMAIN/timeout) for anything not explicitly configured, so callers
    exercise the same try/except-per-record-type path as production."""
    def __init__(self, answers):
        self._answers = answers

    async def resolve(self, name, rtype):
        key = (name, rtype)
        if key not in self._answers:
            raise Exception(f"no answer for {name} {rtype}")
        return self._answers[key]


async def test_dns_lookup_parses_all_record_types(monkeypatch):
    answers = {
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        ("example.com", "MX"): [_FakeMXRecord("mail.example.com", 10)],
        ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
        ("example.com", "TXT"): [_FakeTXTRecord("v=spf1 -all")],
        ("example.com", "SOA"): [_FakeSOARecord("a.iana-servers.net")],
    }
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))
    out = await intel.dns_lookup("example.com", None)
    assert out["a"] == ["93.184.216.34"]
    assert out["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert out["mx"] == [{"priority": 10, "host": "mail.example.com"}]
    assert out["ns"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert out["txt"] == ["v=spf1 -all"]
    assert out["soa"] == "a.iana-servers.net"


async def test_dns_lookup_missing_records_default_empty(monkeypatch):
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver({}))
    out = await intel.dns_lookup("nx.test", None)
    assert out == {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "soa": None}


def test_classify_mail_provider_matches_known_hosts():
    assert intel._classify_mail_provider("ASPMX.L.GOOGLE.COM") == "Google Workspace"
    assert intel._classify_mail_provider("domain-com.mail.protection.outlook.com") == "Microsoft 365"
    assert intel._classify_mail_provider("mx1.example-corp.internal") is None


async def test_mail_infra_lookup_resolves_ip_and_classifies_provider(monkeypatch):
    answers = {("aspmx.l.google.com", "A"): ["142.250.152.26"]}
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))

    async def fake_get(url, timeout=None):
        assert "142.250.152.26" in url
        return _FakeResp(200, {"org": "AS15169 Google LLC", "country": "US"})
    client = type("C", (), {"get": staticmethod(fake_get)})()

    out = await intel.mail_infra_lookup(client, [{"host": "aspmx.l.google.com", "priority": 1}],
                                        "fake-token", None)
    assert out == [{"host": "aspmx.l.google.com", "priority": 1, "ips": ["142.250.152.26"],
                    "provider": "Google Workspace", "asn": "AS15169", "org": "Google LLC",
                    "country": "US"}]


async def test_mail_infra_lookup_dedupes_shared_mx_host(monkeypatch):
    answers = {("mx.example.com", "A"): ["1.2.3.4"]}
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))

    async def fake_get(url, timeout=None):
        return _FakeResp(200, {})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    mx_records = [{"host": "mx.example.com", "priority": 10}, {"host": "mx.example.com", "priority": 20}]
    out = await intel.mail_infra_lookup(client, mx_records, None, None)
    assert len(out) == 1
    assert out[0]["priority"] == 10                  # first occurrence kept


async def test_mail_infra_lookup_keyless_still_enriches_asn_org(monkeypatch):
    # IPinfo's /json endpoint works without a token — ASN/org enrichment
    # must not be skipped outright just because no key is configured.
    answers = {("mx.unrecognized.test", "A"): ["9.9.9.9"]}
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))

    async def fake_get(url, timeout=None):
        assert "token=" not in url
        return _FakeResp(200, {"org": "AS64512 Example Net", "country": "US"})
    client = type("C", (), {"get": staticmethod(fake_get)})()

    out = await intel.mail_infra_lookup(client, [{"host": "mx.unrecognized.test", "priority": 5}],
                                        None, None)
    assert out == [{"host": "mx.unrecognized.test", "priority": 5, "ips": ["9.9.9.9"],
                    "provider": None, "asn": "AS64512", "org": "Example Net", "country": "US"}]


# --------------------------------------------------------------------------- #
# Search-engine dorking (Google Custom Search API)
# --------------------------------------------------------------------------- #
def test_parse_cse_response_extracts_hits():
    data = {"items": [{"title": "Admin", "link": "https://x.com/admin", "snippet": "login"},
                      {"title": "No link"}]}   # missing link -> skipped
    out = dorking._parse_cse_response(data)
    assert out == [{"title": "Admin", "link": "https://x.com/admin", "snippet": "login"}]


def test_parse_cse_response_empty_on_missing_items():
    assert dorking._parse_cse_response({}) == []
    assert dorking._parse_cse_response({"error": {"code": 403}}) == []


async def test_google_dork_tags_category_severity_and_dedupes_by_link(monkeypatch):
    calls = []

    async def fake_get(url, params=None, timeout=None):
        calls.append(params)
        # every category "finds" the same URL -> should collapse to one hit
        return _FakeResp(200, {"items": [{"title": "Admin", "link": "https://x.com/admin",
                                          "snippet": "s"}]})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.google_dork(client, "x.com", "key", "cx", limiter)
    assert len(calls) == len(dorking.DORK_TEMPLATES)          # one query per template
    assert len(out) == 1                                       # deduped by link
    assert out[0]["category"] == dorking.DORK_TEMPLATES[0][0]  # first template wins
    assert out[0]["severity"] == dorking.DORK_TEMPLATES[0][2]
    assert terminal is False
    # scoped via siteSearch/siteSearchFilter (API-level), not a `site:` prefix folded
    # into the free-text query — several templates contain top-level OR, and a
    # `site:x.com` prefix only binds to the first OR branch, leaking later branches
    # to results outside the domain.
    assert all(c["siteSearch"] == "x.com" and c["siteSearchFilter"] == "i" for c in calls)
    assert all("site:" not in c["q"] for c in calls)


async def test_google_dork_stops_on_403_quota_or_bad_key(monkeypatch):
    async def fake_get(url, params=None, timeout=None):
        return _FakeResp(403)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.google_dork(client, "x.com", "bad-key", "cx", limiter)
    assert out == []
    assert terminal is True


async def test_google_dork_stops_on_400_bad_request():
    async def fake_get(url, params=None, timeout=None):
        return _FakeResp(400)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.google_dork(client, "x.com", "key", "bad-cx", limiter)
    assert out == []
    assert terminal is True


async def test_google_dork_network_exception_not_terminal():
    async def fake_get(url, params=None, timeout=None):
        raise Exception("boom")
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.google_dork(client, "x.com", "key", "cx", limiter)
    assert out == []
    assert terminal is False


async def test_google_dork_terminal_status_stops_remaining_domains_in_core_loop():
    """
    Mirrors core.py's `for d in domains: ... if terminal: break` wiring —
    the second domain must never be queried once the first returns terminal.
    """
    queried_domains = []

    async def fake_dork(client, domain, key, cx, limiter):
        queried_domains.append(domain)
        return [], True   # simulate a terminal 403 on the very first domain

    domains = ["a.com", "b.com", "c.com"]
    dorks = []
    for d in domains:
        hits, terminal = await fake_dork(None, d, "key", "cx", None)
        dorks += hits
        if terminal:
            break
    assert queried_domains == ["a.com"]
    assert dorks == []


# --------------------------------------------------------------------------- #
# VirusTotal domain intelligence (historical IP resolutions, WHOIS mirror)
# --------------------------------------------------------------------------- #
_VT_DOMAIN_RESPONSE = {
    "data": {
        "attributes": {
            "reputation": -5,
            "creation_date": 1000000000,             # 2001-09-09T01:46:40+00:00
            "last_modification_date": 1700000000,
            "whois": "Domain Name: X.COM\nRegistrar: Example Registrar",
            "whois_date": 1699000000,
            "categories": {"vendor1": "search engines"},
            "last_dns_records": [{"type": "A", "value": "1.2.3.4", "ttl": 300}],
            "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70},
        }
    }
}

_VT_RESOLUTIONS_RESPONSE = {
    "data": [
        {"attributes": {"ip_address": "1.2.3.4", "date": 1700000000}},
        {"attributes": {"ip_address": "5.6.7.8", "date": 1600000000}},
        {"attributes": {}},   # malformed entry, no ip_address -> skipped
    ]
}


def test_unix_to_iso_converts_and_handles_none():
    assert vt._unix_to_iso(1000000000) == "2001-09-09T01:46:40+00:00"
    assert vt._unix_to_iso(None) is None
    assert vt._unix_to_iso("not-a-number") is None


def test_parse_vt_domain_extracts_all_fields():
    out = vt._parse_vt_domain(_VT_DOMAIN_RESPONSE)
    assert out["reputation"] == -5
    assert out["creation_date"] == "2001-09-09T01:46:40+00:00"
    assert out["whois"].startswith("Domain Name: X.COM")
    assert out["malicious_votes"] == 2
    assert out["suspicious_votes"] == 1
    assert out["last_dns_records"] == [{"type": "A", "value": "1.2.3.4"}]


def test_parse_vt_domain_handles_missing_data_gracefully():
    out = vt._parse_vt_domain({})
    assert out["reputation"] is None
    assert out["malicious_votes"] == 0
    assert out["last_dns_records"] == []


def test_parse_vt_resolutions_sorted_newest_first_and_skips_malformed():
    out = vt._parse_vt_resolutions(_VT_RESOLUTIONS_RESPONSE)
    assert len(out) == 2                              # malformed entry dropped
    assert out[0]["ip"] == "1.2.3.4"                  # 2023-11-... newest
    assert out[1]["ip"] == "5.6.7.8"                  # 2020-09-... older


async def test_vt_domain_lookup_parses_200_response():
    async def fake_get(url, headers=None, timeout=None):
        assert headers["x-apikey"] == "vtkey"
        return _FakeResp(200, _VT_DOMAIN_RESPONSE)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await vt.vt_domain_lookup(client, "x.com", "vtkey")
    assert out["reputation"] == -5


async def test_vt_domain_lookup_returns_empty_on_401():
    async def fake_get(url, headers=None, timeout=None):
        return _FakeResp(401)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await vt.vt_domain_lookup(client, "x.com", "bad-key")
    assert out == {}


async def test_vt_ip_history_parses_resolutions():
    async def fake_get(url, headers=None, params=None, timeout=None):
        assert params["limit"] == 20
        return _FakeResp(200, _VT_RESOLUTIONS_RESPONSE)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await vt.vt_ip_history(client, "x.com", "vtkey")
    assert len(out) == 2
    assert out[0]["ip"] == "1.2.3.4"


async def test_vt_domain_intel_combines_both_calls_and_waits_on_shared_limiter():
    wait_count = 0

    class _FakeLimiter:
        async def wait(self):
            nonlocal wait_count
            wait_count += 1

    call_urls = []

    async def fake_get(url, headers=None, params=None, timeout=None):
        call_urls.append(url)
        if url.endswith("/resolutions"):
            return _FakeResp(200, _VT_RESOLUTIONS_RESPONSE)
        return _FakeResp(200, _VT_DOMAIN_RESPONSE)
    client = type("C", (), {"get": staticmethod(fake_get)})()

    out = await vt.vt_domain_intel(client, "x.com", "vtkey", _FakeLimiter())
    assert wait_count == 2                            # one wait per call
    assert out["reputation"] == -5
    assert len(out["ip_history"]) == 2


async def test_vt_domain_intel_returns_empty_when_vt_has_nothing():
    async def fake_get(url, headers=None, params=None, timeout=None):
        return _FakeResp(404)
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out = await vt.vt_domain_intel(client, "unseen-domain.test", "vtkey", limiter)
    assert out == {}


def test_summarize_entry_points_includes_dork_hits():
    dorks = [{"category": "git-exposure", "severity": "high", "title": "Index of /.git",
             "link": "https://x.com/.git/", "snippet": "Index of /.git"}]
    eps = intel.summarize_entry_points([], {"detected": False, "candidates": {}}, [], {}, [], [],
                                       dorks=dorks)
    assert len(eps) == 1
    assert eps[0]["type"] == "dork-hit"
    assert eps[0]["severity"] == "high"
    assert eps[0]["target"] == "https://x.com/.git/"
    assert eps[0]["attck"] == "T1593.002"


def test_summarize_entry_points_dorks_default_to_none_backward_compatible():
    # existing 6-positional-arg call sites (pre-dorking) must still work
    assert intel.summarize_entry_points([], {"detected": False, "candidates": {}}, [], {}, [], []) == []


def test_summarize_entry_points_ranks_critical_first():
    hosts = [
        Host("dev.x.com", cname="dev.x.com.s3.amazonaws.com",
             takeover="Dangling CNAME -> dev.x.com.s3.amazonaws.com (s3.amazonaws.com); "
                      "unclaimed-service signature matched"),
        Host("legacy.x.com", vulns=["CVE-2026-1"]),
    ]
    cf = {"detected": True, "candidates": {"1.2.3.4": {"confirmed": True, "evidence": "e"}}}
    buckets = [{"name": "x-backup", "provider": "s3", "url": "https://x-backup.s3.amazonaws.com",
                "status": 200, "public": True}]
    eps = intel.summarize_entry_points(hosts, cf, buckets, {}, [], [])
    assert [e["type"] for e in eps][0] == "subdomain-takeover"
    assert eps[0]["severity"] == "critical"
    assert {"cloudflare-origin-bypass", "public-bucket", "known-cve"} <= {e["type"] for e in eps}


def test_summarize_entry_points_empty_when_nothing_found():
    hosts = [Host("a.x.com")]
    cf = {"detected": False, "candidates": {}}
    assert intel.summarize_entry_points(hosts, cf, [], {}, [], []) == []


def test_summarize_entry_points_flags_non_web_ports():
    h = Host("db.x.com", ports=[80, 443, 3389, 6379])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    nwp = [e for e in eps if e["type"] == "non-web-port"]
    assert len(nwp) == 1
    assert nwp[0]["target"] == "db.x.com"
    assert "3389 (RDP)" in nwp[0]["summary"]
    assert "6379 (Redis)" in nwp[0]["summary"]
    assert nwp[0]["summary"].endswith("3389 (RDP), 6379 (Redis)")  # only non-web ports listed
    assert nwp[0]["severity"] == "high"                        # worst of RDP/Redis (both high)
    assert nwp[0]["attck"] == "T1046"


def test_summarize_entry_points_no_non_web_port_finding_when_only_web_ports_open():
    h = Host("web.x.com", ports=[80, 443, 8443])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert not [e for e in eps if e["type"] == "non-web-port"]


def test_summarize_entry_points_unlisted_non_web_port_gets_generic_medium():
    h = Host("odd.x.com", ports=[80, 12345])   # not in NON_WEB_PORT_INFO
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    nwp = [e for e in eps if e["type"] == "non-web-port"][0]
    assert "12345" in nwp["summary"]
    assert nwp["severity"] == "medium"


def test_summarize_entry_points_includes_nvd_only_cves():
    # InternetDB gave CPEs but no vulns entries; --nvd found a critical CVE via CPE lookup.
    h = Host("legacy.x.com", nvd_cves=[{"id": "CVE-2026-9999", "cvss": 9.8}])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert eps[0]["type"] == "known-cve"
    assert eps[0]["severity"] == "critical"
    assert "CVE-2026-9999" in eps[0]["summary"]


def test_summarize_entry_points_notes_tech_confirmed_status():
    cf = {"detected": False, "candidates": {}}
    confirmed = Host("a.x.com", vulns=["CVE-2026-1"], tech_confirmed=True)
    unconfirmed = Host("b.x.com", vulns=["CVE-2026-2"], tech_confirmed=False)
    unknown = Host("c.x.com", vulns=["CVE-2026-3"], tech_confirmed=None)
    eps = intel.summarize_entry_points([confirmed, unconfirmed, unknown], cf, [], {}, [], [])
    by_target = {e["target"]: e["summary"] for e in eps}
    assert "[tech-stack confirmed live]" in by_target["a.x.com"]
    assert "[unconfirmed" in by_target["b.x.com"]
    assert "[tech-stack confirmed live]" not in by_target["c.x.com"]
    assert "[unconfirmed" not in by_target["c.x.com"]


def test_summarize_entry_points_merges_vulns_and_nvd_by_max_cvss():
    h = Host("legacy.x.com", vulns=["CVE-2026-1"],
             nvd_cves=[{"id": "CVE-2026-1", "cvss": 5.0}, {"id": "CVE-2026-2", "cvss": 8.5}])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert eps[0]["severity"] == "high"               # driven by max CVSS 8.5, not the default medium
    assert "CVE-2026-1" in eps[0]["summary"] and "CVE-2026-2" in eps[0]["summary"]


def test_summarize_entry_points_excludes_dos_only_cves_and_surfaces_descriptions():
    h = Host("legacy.x.com", vulns=["CVE-2026-DOS", "CVE-2026-RCE"],
             nvd_cves=[
                 {"id": "CVE-2026-DOS", "cvss": 7.5, "dos_only": True, "desc": "Denial of service crash"},
                 {"id": "CVE-2026-RCE", "cvss": 6.1, "dos_only": False, "desc": "Auth bypass leads to RCE"},
             ])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert "CVE-2026-DOS" not in eps[0]["summary"]
    assert "CVE-2026-RCE" in eps[0]["summary"] and "Auth bypass leads to RCE" in eps[0]["summary"]
    assert "1 DoS-only CVE(s) excluded" in eps[0]["summary"]
    assert eps[0]["severity"] == "medium"              # driven by the surviving CVE's CVSS 6.1, not the DoS one's 7.5


def test_summarize_entry_points_skips_host_with_only_dos_cves():
    h = Host("dos-only.x.com", nvd_cves=[{"id": "CVE-2026-DOS", "cvss": 7.5, "dos_only": True}])
    cf = {"detected": False, "candidates": {}}
    assert intel.summarize_entry_points([h], cf, [], {}, [], []) == []


def test_summarize_entry_points_ranks_by_cvss_not_alphabetically():
    # Alphabetically CVE-2007-... sorts first; by severity it should sort last.
    h = Host("legacy.x.com", vulns=["CVE-2007-4723", "CVE-2024-9999"],
             nvd_cves=[
                 {"id": "CVE-2007-4723", "cvss": 2.1, "desc": "Minor info leak"},
                 {"id": "CVE-2024-9999", "cvss": 9.8, "desc": "Unauthenticated RCE"},
             ])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    summary = eps[0]["summary"]
    assert summary.index("CVE-2024-9999") < summary.index("CVE-2007-4723")
    assert eps[0]["severity"] == "critical"


def test_summarize_entry_points_truncates_large_cve_lists_with_a_count():
    vulns = [f"CVE-2026-{i}" for i in range(63)]              # unscored — no --nvd data
    h = Host("legacy.x.com", vulns=vulns)
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    summary = eps[0]["summary"]
    assert summary.startswith("63 known CVE(s)")
    assert "+58 more" in summary                              # 63 - 5 shown
    assert "run --nvd for full data" in summary                # all 63 unscored -> hint to enrich
    assert eps[0]["severity"] == "medium"                      # no CVSS data at all -> fallback


def test_cve_severity_below_medium_threshold_is_low_not_medium():
    assert intel._cve_severity(3.1) == "low"
    assert intel._cve_severity(0.0) == "low"
    assert intel._cve_severity(None) == "medium"      # missing CVSS still falls back to medium


def test_summarize_entry_points_low_cvss_nvd_cve_ranks_low():
    h = Host("legacy.x.com", nvd_cves=[{"id": "CVE-2026-1", "cvss": 3.1}])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert eps[0]["severity"] == "low"


async def test_cloudflare_origin_detects_unproxied_leak():
    nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    hosts = {
        "x.com":     Host("x.com", ips=["104.16.5.5"]),        # CF edge
        "dev.x.com": Host("dev.x.com", ips=["45.79.10.20"]),   # leaked origin
    }

    async def fake_get(url, timeout=None):
        return _FakeResp(200, {})   # no org data in the response
    client = type("C", (), {"get": staticmethod(fake_get)})()
    res = await intel.cloudflare_origin_analysis(
        client, None, ["x.com"], hosts, {}, nets, active=False, resolver_ns=None)
    assert res["detected"] is True
    assert "x.com" in res["fronted"]
    assert "45.79.10.20" in res["candidates"]
    assert res["candidates"]["45.79.10.20"]["asn"] is None


async def test_cloudflare_origin_enriches_keylessly_without_ipinfo_token():
    # IPinfo's /json endpoint works without a token (lower, unauthenticated
    # rate limit) — ASN/org enrichment for CF-origin candidates must not be
    # skipped outright just because no --ipinfo-key/IPINFO_TOKEN is set.
    nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    hosts = {
        "x.com":     Host("x.com", ips=["104.16.5.5"]),
        "dev.x.com": Host("dev.x.com", ips=["45.79.10.20"]),
    }

    async def fake_get(url, timeout=None):
        assert "token=" not in url
        return _FakeResp(200, {"org": "AS63949 Linode, LLC"})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    res = await intel.cloudflare_origin_analysis(
        client, None, ["x.com"], hosts, {}, nets, active=False, resolver_ns=None)
    assert res["candidates"]["45.79.10.20"]["asn"] == "AS63949"


async def test_cloudflare_origin_enriches_candidates_with_asn_org(monkeypatch):
    nets = [ipaddress.ip_network(c) for c in CF_FALLBACK]
    hosts = {
        "x.com":     Host("x.com", ips=["104.16.5.5"]),
        "dev.x.com": Host("dev.x.com", ips=["45.79.10.20"]),
    }

    async def fake_get(url, timeout=None):
        assert "45.79.10.20" in url
        return _FakeResp(200, {"org": "AS63949 Linode, LLC", "country": "US"})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    res = await intel.cloudflare_origin_analysis(
        client, None, ["x.com"], hosts, {"ipinfo": "fake-token"}, nets,
        active=False, resolver_ns=None)
    cand = res["candidates"]["45.79.10.20"]
    assert cand["asn"] == "AS63949"
    assert cand["org"] == "Linode, LLC"


# --------------------------------------------------------------------------- #
# State: diffing
# --------------------------------------------------------------------------- #
def test_diff_snapshot_new_gone_and_ports():
    prev = {"ts": "2026-01-01", "hosts": {
        "a.x.com": {"ips": ["1.1.1.1"], "ports": [80]},
        "old.x.com": {"ips": ["2.2.2.2"], "ports": []},
    }}
    cur = [Host("a.x.com", ips=["1.1.1.1"], ports=[80, 443]),
           Host("new.x.com", ips=["3.3.3.3"], ports=[22])]
    d = state.diff_snapshot(prev, cur)
    assert d["new_hosts"] == ["new.x.com"]
    assert d["gone_hosts"] == ["old.x.com"]
    assert d["new_ports"] == {"a.x.com": [443]}


# --------------------------------------------------------------------------- #
# ProjectDiscovery backend parsers (monkeypatched subprocess output)
# --------------------------------------------------------------------------- #
async def test_dnsx_parse(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=900):
        return '{"host":"www.x.com","a":["1.2.3.4"],"aaaa":[],"cname":["cdn.x.com."]}'
    monkeypatch.setattr(backends, "_run", fake_run)
    res = await backends.dnsx_resolve(["www.x.com"])
    assert res["www.x.com"]["a"] == ["1.2.3.4"]
    assert res["www.x.com"]["cname"] == "cdn.x.com"


async def test_httpx_parse(monkeypatch):
    monkeypatch.setattr(backends, "pd_httpx_bin", lambda: "httpx")
    async def fake_run(cmd, stdin=None, timeout=900):
        return ('{"input":"x.com","url":"https://x.com","status_code":200,'
                '"title":"Home","webserver":"nginx","tech":["React"],"favicon":"-9"}')
    monkeypatch.setattr(backends, "_run", fake_run)
    res = await backends.httpx_probe(["x.com"])
    assert res["x.com"]["status"] == 200
    assert res["x.com"]["tech"] == ["React"]
    assert res["x.com"]["favicon"] == "-9"


async def test_nuclei_parse(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=1800):
        return ('{"host":"x.com","template-id":"t","matched-at":"https://x.com",'
                '"info":{"name":"Bug","severity":"high",'
                '"classification":{"cve-id":["CVE-2026-1"]}}}')
    monkeypatch.setattr(backends, "_run", fake_run)
    res = await backends.nuclei_scan(["https://x.com"])
    assert res[0]["severity"] == "high"
    assert res[0]["cve"] == ["CVE-2026-1"]


async def test_naabu_parse(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=300):
        return '{"ip":"1.2.3.4","port":443}\n{"ip":"1.2.3.4","port":80}'
    monkeypatch.setattr(backends, "_run", fake_run)
    res = await backends.naabu_scan("1.2.3.4")
    assert res == [80, 443]


def test_available_backends_shape():
    bk = backends.available_backends()
    assert set(bk) == {"subfinder", "dnsx", "httpx", "naabu", "nuclei", "psql (crt.sh)"}
    assert all(isinstance(v, bool) for v in bk.values())


# --------------------------------------------------------------------------- #
# Reporting: CSV target list
# --------------------------------------------------------------------------- #
def test_write_csv_has_subdomain_ips_and_per_ip_asn_org():
    hosts = [
        Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC",
             country="US", scheme="https", http_status=200, source={"crtsh"},
             ip_asn={"1.2.3.4": "AS15169"}, ip_org={"1.2.3.4": "Google LLC"}),
        # multi-IP host, only one IP resolved to an ASN/org — both columns
        # stay positionally parallel to ips, blank where unresolved.
        Host("multi.x.com", ips=["9.9.9.9", "8.8.8.8"], wildcard=True, source={"seed"},
             ip_asn={"8.8.8.8": "AS15169"}, ip_org={"8.8.8.8": "Google LLC"}),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        n = report.write_csv(hosts, str(path))
        assert n == 2
        rows = list(csv.DictReader(path.open()))
    assert list(rows[0].keys()) == ["subdomain", "ips", "asn", "org"]
    assert rows[0]["subdomain"] == "a.x.com"
    assert rows[0]["ips"] == "1.2.3.4"
    assert rows[0]["asn"] == "AS15169"
    assert rows[0]["org"] == "Google LLC"
    assert rows[1]["subdomain"] == "multi.x.com"
    assert rows[1]["ips"] == "9.9.9.9, 8.8.8.8"
    assert rows[1]["asn"] == ", AS15169"          # blank for 9.9.9.9, resolved for 8.8.8.8
    assert rows[1]["org"] == ", Google LLC"


def test_write_csv_single_ip_host_falls_back_to_scalar_asn_org():
    # ip_asn/ip_org weren't populated (e.g. a caller of apply_ipinfo() that
    # omitted the optional ip arg), but h.asn/h.org are known and
    # unambiguous for one IP.
    h = Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        report.write_csv([h], str(path))
        rows = list(csv.DictReader(path.open()))
    assert rows[0]["asn"] == "AS15169"
    assert rows[0]["org"] == "Google LLC"


# --------------------------------------------------------------------------- #
# Reporting: CF-origin-candidate IP list (nmap/nuclei handoff)
# --------------------------------------------------------------------------- #
def test_write_origin_ips_includes_confirmed_and_unconfirmed_sorted():
    cf = {"detected": True, "fronted": ["x.com"],
          "candidates": {
              "45.79.10.20": {"sources": ["unproxied:dev.x.com"], "confirmed": True},
              "9.9.9.9": {"sources": ["spf:x.com"], "confirmed": False},
          }}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.origin_ips.txt"
        n = report.write_origin_ips(cf, str(path))
        content = path.read_text()
    assert n == 2
    assert content == "45.79.10.20\n9.9.9.9\n"       # sorted, one per line


def test_write_origin_ips_empty_when_no_candidates():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.origin_ips.txt"
        n = report.write_origin_ips({"detected": False, "candidates": {}}, str(path))
        content = path.read_text()
    assert n == 0
    assert content == ""


def test_write_origin_ips_handles_missing_cf_key_gracefully():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.origin_ips.txt"
        n = report.write_origin_ips({}, str(path))
        assert n == 0
        n2 = report.write_origin_ips(None, str(path))
        assert n2 == 0


# --------------------------------------------------------------------------- #
# Reporting: HTML report — collapsible sections + escaping
# --------------------------------------------------------------------------- #
def test_write_html_minimal_data_does_not_crash_and_has_attack_surface():
    hosts = [Host("a.x.com", ips=["1.2.3.4"], http_status=200, scheme="https")]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], {}, str(path))
        content = path.read_text()
    assert content.startswith("<!doctype html>")
    assert 'id="attacksurface"' in content
    assert "a.x.com" in content
    # sections with no data must not render at all
    for absent in ("id=\"sources\"", "id=\"takeover\"", "id=\"cforigin\"", "id=\"people\""):
        assert absent not in content


def test_write_html_escapes_attacker_controlled_strings():
    hosts = [Host("<script>alert(1)</script>.x.com", ips=["1.2.3.4"],
                  server="<img src=x onerror=alert(2)>",
                  takeover='XSS" onmouseover="alert(3)')]
    res = {"entry_points": [{"severity": "critical", "target": hosts[0].subdomain,
                            "summary": "<script>evil()</script>", "attck": "T1"}]}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert "<script>alert(1)</script>" not in content
    assert "<img src=x onerror=alert(2)>" not in content
    assert 'onmouseover="alert(3)' not in content
    assert "<script>evil()</script>" not in content
    assert "&lt;script&gt;" in content


def test_write_html_renders_sections_only_when_data_present():
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = {
        "per_source": {"crtsh": 5},
        "breach": {"x.com": [{"name": "BigBreach", "date": "2022-01-01", "pwned": 100, "data": ["Emails"]}]},
        "buckets": [{"name": "x-backup", "provider": "s3", "url": "https://x", "status": 200, "public": True}],
    }
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert 'id="sources"' in content
    assert 'id="breach"' in content
    assert 'id="buckets"' in content
    assert "BigBreach" in content
    assert "x-backup" in content
    # sections with no data still absent
    assert 'id="nuclei"' not in content
    assert 'id="people"' not in content


def test_write_html_highlights_non_web_ports_in_attack_surface():
    hosts = [Host("db.x.com", ips=["1.2.3.4"], ports=[80, 443, 3389])]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], {}, str(path))
        content = path.read_text()
    assert '<span class="portflag"' in content
    assert ">3389</span>" in content
    assert "needs manual review" in content


def test_write_html_no_portflag_note_when_only_web_ports_open():
    hosts = [Host("web.x.com", ips=["1.2.3.4"], ports=[80, 443])]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], {}, str(path))
        content = path.read_text()
    assert '<span class="portflag"' not in content


def test_write_markdown_bolds_non_web_ports():
    hosts = [Host("db.x.com", ips=["1.2.3.4"], ports=[80, 443, 3389])]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown(hosts, ["x.com"], {}, str(path))
        content = path.read_text()
    assert "80, 443, **3389**" in content
    assert "need a manual look" in content


def test_write_html_cve_section_shows_tech_confirmed_badge():
    hosts = [Host("a.x.com", ips=["1.2.3.4"], vulns=["CVE-2026-1"], tech_confirmed=True),
             Host("b.x.com", ips=["5.6.7.8"], vulns=["CVE-2026-2"], tech_confirmed=False)]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], {}, str(path))
        content = path.read_text()
    assert "TECH-CONFIRMED" in content
    assert "UNCONFIRMED" in content
    assert "CVE-2026-1" in content and "CVE-2026-2" in content


def test_write_html_vt_section_shows_intel_and_ip_history():
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = {"vt": {"x.com": {"reputation": -5, "malicious_votes": 2, "suspicious_votes": 1,
                            "creation_date": "2001-09-09T01:46:40+00:00",
                            "last_modification_date": "2023-11-14T22:13:20+00:00",
                            "ip_history": [{"ip": "1.2.3.4", "first_seen": "2023-11-14T22:13:20+00:00"},
                                          {"ip": "5.6.7.8", "first_seen": "2020-09-13T12:26:40+00:00"}]}}}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert 'id="vt"' in content
    assert "-5" in content
    assert "5.6.7.8" in content
    assert "hosting history" in content.lower()


def test_write_markdown_vt_section_renders_history_table():
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = {"vt": {"x.com": {"reputation": 0, "malicious_votes": 0, "suspicious_votes": 0,
                            "creation_date": None, "last_modification_date": None,
                            "ip_history": [{"ip": "9.9.9.9", "first_seen": "2024-01-01T00:00:00+00:00"}]}}}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert "VirusTotal" in content
    assert "9.9.9.9" in content
    assert "2024-01-01T00:00:00+00:00" in content


def test_write_html_whois_section_shows_domain_even_when_rdap_lookup_failed():
    # core.py always populates one whois entry per domain, even on a total
    # RDAP lookup failure (unsupported TLD, network issue, domain not
    # found) — the section must still render that domain's row rather than
    # vanishing entirely just because every field came back empty.
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = {"whois": {"x.com": {"registrar": None, "created": None, "expires": None,
                               "last_changed": None, "nameservers": [], "status": [],
                               "registrant_name": None, "registrant_org": None,
                               "privacy_protected": None, "privacy_provider": None}}}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert 'id="whois"' in content
    assert "x.com" in content
    assert "Unknown" in content


def test_write_html_export_buttons_reference_a_table_id_that_exists():
    import re
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = {"entry_points": [{"severity": "high", "target": "a.x.com", "summary": "x", "attck": "T1"}]}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    referenced_ids = set(re.findall(r"exportTableToCSV\('([^']+)'", content))
    table_ids = set(re.findall(r'<table id="([^"]+)"', content))
    assert referenced_ids and referenced_ids <= table_ids


# --------------------------------------------------------------------------- #
# OSINT user enumeration (people.py) — pure-logic parsers + pattern generation
# --------------------------------------------------------------------------- #
def test_parse_hunter_response_extracts_pattern_and_people():
    data = {"data": {"pattern": "{first}.{last}",
                     "emails": [
                         {"value": "Jane.Doe@x.com", "first_name": "Jane", "last_name": "Doe",
                          "position": "Engineer", "confidence": 91, "type": "personal"},
                         {"value": "info@x.com", "type": "generic"},
                     ]}}
    pattern, ppl = people._parse_hunter_response(data)
    assert pattern == "{first}.{last}"
    assert len(ppl) == 2
    named = next(p for p in ppl if p.email == "jane.doe@x.com")       # lowercased
    assert named.name == "Jane Doe"
    assert named.confidence == 91
    assert "hunter" in named.source
    role = next(p for p in ppl if p.email == "info@x.com")
    assert role.name is None


def test_parse_hunter_response_skips_entries_without_a_value():
    pattern, ppl = people._parse_hunter_response({"data": {"emails": [{"first_name": "No"}]}})
    assert ppl == []


def test_extract_emails_from_text_matches_finds_addresses_at_domain():
    items = [{"text_matches": [{"fragment": "contact John.Smith@x.com or Jane@x.com for access"}]},
             {"text_matches": [{"fragment": "unrelated bob@other.com"}]}]
    out = people._extract_emails_from_text_matches(items, "x.com")
    assert out == {"john.smith@x.com", "jane@x.com"}


def test_extract_emails_from_text_matches_rejects_longer_domain_suffix():
    # alice@x.com.au and alice@x.company are NOT x.com addresses — a missing
    # boundary check after the domain would truncate them into false hits.
    items = [{"text_matches": [{"fragment": "alice@x.com.au reached out, so did bob@x.company"}]}]
    assert people._extract_emails_from_text_matches(items, "x.com") == set()


def test_extract_emails_from_text_matches_accepts_domain_at_string_end_or_before_punctuation():
    items = [{"text_matches": [{"fragment": "contact: alice@x.com."}]},
             {"text_matches": [{"fragment": "bob@x.com"}]}]
    out = people._extract_emails_from_text_matches(items, "x.com")
    assert out == {"alice@x.com", "bob@x.com"}


# --------------------------------------------------------------------------- #
# -iL / --domains-file
# --------------------------------------------------------------------------- #
def test_read_domains_file_skips_blank_lines_and_comments():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "domains.txt"
        path.write_text("a.com\n# a comment\n\nb.com\n  \nc.com\n")
        assert cli.read_domains_file(str(path)) == ["a.com", "b.com", "c.com"]


def test_merge_domains_dedupes_and_preserves_order():
    assert cli.merge_domains(["c.com"], ["a.com", "b.com", "a.com"]) == ["c.com", "a.com", "b.com"]
    assert cli.merge_domains([], ["a.com"]) == ["a.com"]
    assert cli.merge_domains(["a.com"], []) == ["a.com"]


def test_apply_all_flag_enables_osint_checks_not_active_ones():
    args = argparse.Namespace(all=True, buckets=False, dork=False, vt=False, nvd=False,
                              nuclei=False, asn_expand=False, active_ports=False,
                              verify_emails=False, passive_only=False)
    cli.apply_all_flag(args)
    assert args.buckets is True
    assert args.dork is True
    assert args.vt is True
    assert args.nvd is True
    assert args.nuclei is True
    assert args.asn_expand is True
    # active/target-touching checks must never be flipped on by --all
    assert args.active_ports is False
    assert args.verify_emails is False


def test_apply_all_flag_is_noop_when_not_set():
    args = argparse.Namespace(all=False, buckets=False, dork=False, vt=False, nvd=False,
                              nuclei=False, asn_expand=False)
    cli.apply_all_flag(args)
    assert args.buckets is False
    assert args.dork is False
    assert args.vt is False
    assert args.nvd is False
    assert args.nuclei is False
    assert args.asn_expand is False


def test_all_flag_parses_via_real_argparse_and_expands_correctly(monkeypatch):
    # exercises the real ap.parse_args() -> apply_all_flag() path, not just
    # the pure function in isolation.
    monkeypatch.setattr(sys, "argv", ["lrecon", "--all", "--check-backends"])

    async def fake_selfcheck(active=False):
        return [{"tool": "subfinder", "path": True, "ran": True, "parsed": 1, "note": "ok"}]
    monkeypatch.setattr(cli.backends, "selfcheck", fake_selfcheck)
    cli.main()   # --check-backends returns early, but args are parsed+expanded first


def test_domains_file_missing_raises_cli_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["lrecon", "-iL", "/nonexistent/path/domains.txt"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "--domains-file" in capsys.readouterr().err


def test_verify_emails_conflicts_with_passive_only(monkeypatch, capsys):
    # --verify-emails opens an SMTP connection to the target's own MX — that
    # must be rejected under --passive-only's zero-target-touch guarantee.
    monkeypatch.setattr(sys, "argv", ["lrecon", "--passive-only", "--verify-emails", "x.com"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "--verify-emails conflicts with --passive-only" in capsys.readouterr().err


def test_apply_pattern_supports_first_last_f_l_tokens():
    assert people._apply_pattern("{first}.{last}", "Jane", "Doe", "x.com") == "jane.doe@x.com"
    assert people._apply_pattern("{f}{last}", "Jane", "Doe", "x.com") == "jdoe@x.com"
    assert people._apply_pattern("{first}{l}", "Jane", "Doe", "x.com") == "janed@x.com"


def test_apply_pattern_unrecognized_token_returns_none():
    assert people._apply_pattern("{middle}.{last}", "Jane", "Doe", "x.com") is None


def test_apply_pattern_missing_name_part_returns_none():
    assert people._apply_pattern("{first}.{last}", "", "Doe", "x.com") is None


def test_generate_candidate_emails_from_names_and_pattern():
    names = [{"name": "Jane Doe", "position": "CTO"}, {"name": "SingleName"}, {"name": None}]
    out = people.generate_candidate_emails(names, "x.com", "{first}.{last}")
    assert len(out) == 1
    p = out[0]
    assert p.email == "jane.doe@x.com"
    assert p.generated is True
    assert p.position == "CTO"
    assert "rocketreach+pattern" in p.source


def test_generate_candidate_emails_no_pattern_yields_nothing():
    assert people.generate_candidate_emails([{"name": "Jane Doe"}], "x.com", None) == []


def test_parse_rocketreach_response_extracts_professional_fields_only():
    data = {"profiles": [
        {"name": "Jane Doe", "current_title": "CTO", "linkedin_url": "https://linkedin.com/in/janedoe",
         "personal_emails": ["jane@gmail.com"], "phones": ["555-1234"]},   # personal fields ignored
        {"full_name": "No Title Guy"},
        {"current_title": "Nameless"},                                    # no name -> skipped
    ]}
    out = people._parse_rocketreach_response(data)
    assert len(out) == 2
    assert out[0] == {"name": "Jane Doe", "position": "CTO",
                      "linkedin_url": "https://linkedin.com/in/janedoe"}
    assert "personal_emails" not in out[0] and "phones" not in out[0]
    assert out[1]["name"] == "No Title Guy"


# --------------------------------------------------------------------------- #
# SMTP RCPT-TO verification
# --------------------------------------------------------------------------- #
class _FakeSMTPReader:
    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


class _FakeSMTPWriter:
    def __init__(self):
        self.sent = []

    def write(self, data):
        self.sent.append(data.decode())

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class _FakeMX:
    def __init__(self, host, preference=10):
        self.exchange = host + "."
        self.preference = preference


class _FakeResolver:
    def __init__(self, mx_host):
        self._mx_host = mx_host

    async def resolve(self, domain, rtype):
        assert rtype == "MX"
        return [_FakeMX(self._mx_host)]


async def test_smtp_read_response_handles_multiline_continuation():
    reader = _FakeSMTPReader([b"250-mail.x.com\r\n", b"250-PIPELINING\r\n", b"250 8BITMIME\r\n"])
    code = await people._smtp_read_response(reader)
    assert code == 250


async def test_verify_emails_catch_all_domain_marks_everything_inconclusive(monkeypatch):
    reader = _FakeSMTPReader([
        b"220 mail.x.com ESMTP\r\n",           # banner
        b"250 mail.x.com\r\n",                 # EHLO
        b"250 OK\r\n",                          # MAIL FROM
        b"250 OK\r\n",                          # RCPT TO (catch-all probe) -> accepted
        b"221 Bye\r\n",                         # QUIT
    ])
    writer = _FakeSMTPWriter()
    monkeypatch.setattr(people, "get_resolver", lambda ns: _FakeResolver("mail.x.com"))
    async def fake_open_connection(host, port):
        return reader, writer
    monkeypatch.setattr(people.asyncio, "open_connection", fake_open_connection)

    out = await people.verify_emails("x.com", ["jane.doe@x.com", "john@x.com"], None)
    assert out == {"jane.doe@x.com": "catch-all", "john@x.com": "catch-all"}


async def test_verify_emails_distinguishes_valid_and_invalid(monkeypatch):
    reader = _FakeSMTPReader([
        b"220 mail.x.com ESMTP\r\n",           # banner
        b"250 mail.x.com\r\n",                 # EHLO
        b"250 OK\r\n",                          # MAIL FROM
        b"550 No such user\r\n",                # RCPT TO (catch-all probe) -> rejected -> not catch-all
        b"250 OK\r\n",                          # RCPT TO jane.doe@x.com -> valid
        b"550 No such user\r\n",                # RCPT TO nobody@x.com -> invalid
        b"221 Bye\r\n",                         # QUIT
    ])
    writer = _FakeSMTPWriter()
    monkeypatch.setattr(people, "get_resolver", lambda ns: _FakeResolver("mail.x.com"))
    async def fake_open_connection(host, port):
        return reader, writer
    monkeypatch.setattr(people.asyncio, "open_connection", fake_open_connection)

    out = await people.verify_emails("x.com", ["jane.doe@x.com", "nobody@x.com"], None)
    assert out == {"jane.doe@x.com": "valid", "nobody@x.com": "invalid"}


async def test_verify_emails_no_mx_returns_unknown(monkeypatch):
    class _NoMXResolver:
        async def resolve(self, domain, rtype):
            raise Exception("NXDOMAIN")
    monkeypatch.setattr(people, "get_resolver", lambda ns: _NoMXResolver())
    out = await people.verify_emails("x.com", ["jane.doe@x.com"], None)
    assert out == {"jane.doe@x.com": "unknown"}


def test_rcpt_status_only_550_is_definitive_rejection():
    assert people._rcpt_status(250) == "valid"
    assert people._rcpt_status(251) == "valid"
    assert people._rcpt_status(550) == "invalid"
    # temp-fail/greylisting and other policy codes are NOT proof of absence
    assert people._rcpt_status(450) == "unknown"
    assert people._rcpt_status(451) == "unknown"
    assert people._rcpt_status(452) == "unknown"
    assert people._rcpt_status(421) == "unknown"
    assert people._rcpt_status(553) == "unknown"


async def test_verify_emails_greylisted_catchall_probe_stays_unknown(monkeypatch):
    # The catch-all probe itself gets a temp-fail (greylisting) — every real
    # address on this connection would hit the same ambiguity, so results
    # must stay at the "unknown" default rather than being probed further
    # and potentially misclassified.
    reader = _FakeSMTPReader([
        b"220 mail.x.com ESMTP\r\n",           # banner
        b"250 mail.x.com\r\n",                 # EHLO
        b"250 OK\r\n",                          # MAIL FROM
        b"450 Greylisted, try again later\r\n", # RCPT TO (catch-all probe) -> ambiguous
    ])
    writer = _FakeSMTPWriter()
    monkeypatch.setattr(people, "get_resolver", lambda ns: _FakeResolver("mail.x.com"))
    async def fake_open_connection(host, port):
        return reader, writer
    monkeypatch.setattr(people.asyncio, "open_connection", fake_open_connection)

    out = await people.verify_emails("x.com", ["jane.doe@x.com"], None)
    assert out == {"jane.doe@x.com": "unknown"}
    # no RCPT TO was sent for the real candidate — only the catch-all probe
    rcpt_lines = [s for s in writer.sent if s.startswith("RCPT")]
    assert len(rcpt_lines) == 1


async def test_verify_emails_non_550_rejection_is_unknown_not_invalid(monkeypatch):
    reader = _FakeSMTPReader([
        b"220 mail.x.com ESMTP\r\n",           # banner
        b"250 mail.x.com\r\n",                 # EHLO
        b"250 OK\r\n",                          # MAIL FROM
        b"550 No such user\r\n",                # RCPT TO (catch-all probe) -> definitive reject
        b"452 Too many recipients\r\n",         # RCPT TO jane.doe@x.com -> temp-fail, not definitive
        b"221 Bye\r\n",                         # QUIT
    ])
    writer = _FakeSMTPWriter()
    monkeypatch.setattr(people, "get_resolver", lambda ns: _FakeResolver("mail.x.com"))
    async def fake_open_connection(host, port):
        return reader, writer
    monkeypatch.setattr(people.asyncio, "open_connection", fake_open_connection)

    out = await people.verify_emails("x.com", ["jane.doe@x.com"], None)
    assert out == {"jane.doe@x.com": "unknown"}


# --------------------------------------------------------------------------- #
# On-boot API key verification
# --------------------------------------------------------------------------- #
class _FakeKeyCheckClient:
    """Routes GET requests to canned responses by URL substring."""
    def __init__(self, responses: dict):
        self._responses = responses
        self.calls = []

    async def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(url)
        for needle, resp in self._responses.items():
            if needle in url:
                return resp
        return _FakeResp(404)


async def test_verify_keys_marks_ready_and_invalid_and_nulls_bad_keys():
    client = _FakeKeyCheckClient({
        "shodan.io/api-info": _FakeResp(200, {"query_credits": 100}),
        "ipinfo.io": _FakeResp(401),
        "api.github.com/user": _FakeResp(200, {"login": "octocat"}),
        "hunter.io/v2/account": _FakeResp(401),
        "rocketreach.co": _FakeResp(200, {}),
    })
    keys = {"shodan": "sk", "ipinfo": "ik", "github": "gk", "hibp": "hk",
            "hunter": "hnk", "rocketreach": "rrk"}
    await core.verify_keys(client, keys)
    assert keys["shodan"] == "sk"                 # 200 -> kept
    assert keys["ipinfo"] is None                 # 401 -> nulled
    assert keys["github"] == "gk"                 # 200 -> kept
    assert keys["hunter"] is None                 # 401 -> nulled
    assert keys["rocketreach"] == "rrk"            # 200 -> kept
    assert keys["hibp"] == "hk"                    # never touched (keyless endpoint, not checked)


async def test_verify_keys_ipinfo_error_in_200_body_counts_as_invalid():
    # IPinfo sometimes returns HTTP 200 with an {"error": ...} body for a bad token.
    client = _FakeKeyCheckClient({"ipinfo.io": _FakeResp(200, {"error": {"title": "Wrong Token"}})})
    keys = {"shodan": None, "ipinfo": "bad", "github": None, "hibp": None,
            "hunter": None, "rocketreach": None}
    await core.verify_keys(client, keys)
    assert keys["ipinfo"] is None


async def test_verify_keys_skips_unconfigured_services():
    client = _FakeKeyCheckClient({})
    keys = {"shodan": None, "ipinfo": None, "github": None, "hibp": None,
            "hunter": None, "rocketreach": None}
    await core.verify_keys(client, keys)
    assert client.calls == []                     # nothing configured -> zero requests made


async def test_verify_keys_check_failure_does_not_null_the_key():
    # A network error/timeout during the check isn't proof the key is bad —
    # only an explicit 401/403 should null it out.
    class _RaisingClient:
        async def get(self, *a, **kw):
            raise TimeoutError("connect timed out")
    keys = {"shodan": "sk", "ipinfo": None, "github": None, "hibp": None,
            "hunter": None, "rocketreach": None}
    await core.verify_keys(_RaisingClient(), keys)
    assert keys["shodan"] == "sk"
