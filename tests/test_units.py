"""Unit tests for LRecon pure-logic and backend parsers (no network required)."""
import argparse
import asyncio
import csv
import ipaddress
import sys
import tempfile
from pathlib import Path

import pytest

import lrecon
from lrecon import (active, enrich, intel, state, backends, sources, report, people, cli,
                    core, dorking, vt, llm, news, dossier)
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


class _FakeRespText:
    """Response whose body is text (bucket listing XML), not JSON."""
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()

    def json(self):
        raise ValueError("not json")


class _FlakyClient:
    """Replays canned responses/exceptions in order; counts calls and records
    the URLs requested (callers assert on query-form alternation)."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.urls = []

    async def get(self, url, timeout=None, **kwargs):
        self.calls += 1
        self.urls.append(url)
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
    client = _FlakyClient([_FakeResp(503)] * 5)
    out = await sources.enum_crtsh(client, "x.com")
    assert out == set()
    assert client.calls == 5
    # Alternates the two query forms so a planner timeout on one form doesn't
    # burn every attempt.
    assert any("?q=" in u for u in client.urls)
    assert any("identity=" in u for u in client.urls)


async def test_enum_crtsh_stops_early_on_non_retryable_4xx(monkeypatch):
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)
    client = _FlakyClient([_FakeResp(404)] * 5)
    out = await sources.enum_crtsh(client, "x.com")
    assert out == set()
    assert client.calls == 1        # 404 won't fix itself — don't burn retries


async def test_enum_crtsh_retries_200_with_non_list_body(monkeypatch):
    """A 200 carrying an HTML error page / dict is a crt.sh failure mode, not an
    empty result — it must be retried, not accepted as 'no certs'."""
    async def no_sleep(*a, **kw):
        return None
    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)
    client = _FlakyClient([
        _FakeResp(200, {"error": "hosed"}),
        _FakeResp(200, [{"name_value": "a.x.com", "common_name": None}]),
    ])
    out = await sources.enum_crtsh(client, "x.com")
    assert out == {"a.x.com"}
    assert client.calls == 2


def test_crtsh_name_in_scope_enforces_label_boundary():
    # A bare endswith() accepts testexample.com for example.com — confirmed
    # live that crt.sh's %.example.com pattern returns such names.
    assert sources._crtsh_name_in_scope("dev.example.com", "example.com") is True
    assert sources._crtsh_name_in_scope("example.com", "example.com") is True
    assert sources._crtsh_name_in_scope("m.testexample.com", "example.com") is False
    assert sources._crtsh_name_in_scope("testexample.com", "example.com") is False
    # rfc822Name subjects are not hosts to scan
    assert sources._crtsh_name_in_scope("subjectname@example.com", "example.com") is False
    assert sources._crtsh_name_in_scope("", "example.com") is False


def test_parse_crtsh_rows_scopes_and_strips(monkeypatch):
    rows = [{"name_value": "*.a.x.com\nb.x.com\nevil.notx.com\nuser@x.com",
             "common_name": "c.x.com."},
            "not-a-dict"]
    assert sources._parse_crtsh_rows(rows, "x.com") == {"a.x.com", "b.x.com", "c.x.com"}


# --------------------------------------------------------------------------- #
# crt.sh direct-Postgres fallback (bypasses the flaky HTTP frontend entirely)
# --------------------------------------------------------------------------- #
async def test_crtsh_psql_parses_rows(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: True)
    seen = {}
    async def fake_run(cmd, stdin=None, timeout=900, env=None):
        seen["timeout"] = timeout
        seen["env"] = env or {}
        return "a.x.com\nb.x.com\n"
    monkeypatch.setattr(backends, "_run", fake_run)
    rows = await backends.crtsh_psql("x.com")
    assert rows == ["a.x.com", "b.x.com"]
    # Short, bounded budgets: raw TCP :5432 hangs rather than refusing where it
    # is firewalled, so an unbounded first tier would stall the whole run.
    assert seen["timeout"] == backends.CRTSH_PSQL_TIMEOUT
    assert seen["env"]["PGCONNECT_TIMEOUT"] == str(backends.CRTSH_PSQL_CONNECT_TIMEOUT)
    assert "statement_timeout" in seen["env"]["PGOPTIONS"]


async def test_crtsh_psql_not_on_path_returns_none(monkeypatch):
    monkeypatch.setattr(backends, "have", lambda t: False)
    assert await backends.crtsh_psql("x.com") is None


async def test_crtsh_psql_empty_output_returns_none(monkeypatch):
    # Covers both a genuinely empty result and a silent connection failure —
    # either way the caller falls back to the HTTP path as cheap insurance.
    monkeypatch.setattr(backends, "have", lambda t: True)
    async def fake_run(cmd, stdin=None, timeout=900, env=None):
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


_S3_LISTING = """<?xml version="1.0"?>
<ListBucketResult><Name>acme</Name><IsTruncated>false</IsTruncated>
<Contents><Key>logo.png</Key><Size>2048</Size></Contents>
<Contents><Key>backups/db.sql</Key><Size>1048576</Size></Contents>
<Contents><Key>.env</Key><Size>512</Size></Contents>
<Contents><Key>assets/</Key><Size>0</Size></Contents>
</ListBucketResult>"""

_AZURE_LISTING = """<?xml version="1.0"?>
<EnumerationResults><Blobs>
<Blob><Name>report.pdf</Name><Properties><Content-Length>4096</Content-Length></Properties></Blob>
<Blob><Name>id_rsa</Name><Properties><Content-Length>1675</Content-Length></Properties></Blob>
</Blobs><NextMarker>abc</NextMarker></EnumerationResults>"""


def test_parse_bucket_listing_s3_keys_sizes_and_interesting():
    out = intel._parse_bucket_listing("s3", "acme", _S3_LISTING)
    keys = [o["key"] for o in out["objects"]]
    assert keys == ["logo.png", "backups/db.sql", ".env"]   # folder placeholder skipped
    assert out["object_count"] == 3
    assert out["bytes"] == 2048 + 1048576 + 512
    assert out["truncated"] is False
    # .sql dump and .env are sensitive; a logo is not
    assert sorted(o["key"] for o in out["interesting"]) == [".env", "backups/db.sql"]


def test_parse_bucket_listing_azure_shape_and_truncation():
    out = intel._parse_bucket_listing("azure", "acme", _AZURE_LISTING)
    assert [o["key"] for o in out["objects"]] == ["report.pdf", "id_rsa"]
    assert out["truncated"] is True                        # NextMarker present
    assert any(o["key"] == "id_rsa" for o in out["interesting"])
    assert out["objects"][1]["size"] == 1675


def test_interesting_object_matches_variant_suffix_forms_not_static_assets():
    """The highest-value keys in the wild are variant forms (.env.production,
    db.sql.gz, config.yml.bak) — anchoring strictly to end-of-string misses
    exactly those. Static assets must not be flagged."""
    sensitive = [".env", ".env.production", ".env.local", "db/prod.sql", "db.sql.gz",
                 "config.yml.bak", "settings.ini.old", "id_rsa", "terraform.tfstate",
                 ".git/config", "creds/password.txt", "backups/2024.zip",
                 ".aws/credentials", "web.config", "users.csv"]
    benign = ["img/logo.png", "css/main.css", "index.html", "fonts/roboto.woff2",
              "video/intro.mp4", "README.md", "favicon.ico"]
    for key in sensitive:
        assert intel._INTERESTING_OBJECT_RE.search(key), f"{key} should be flagged"
    for key in benign:
        assert not intel._INTERESTING_OBJECT_RE.search(key), f"{key} should NOT be flagged"


def test_parse_bucket_listing_malformed_body_is_empty_not_raising():
    out = intel._parse_bucket_listing("s3", "acme", "<html>nope</html>")
    assert out["object_count"] == 0 and out["objects"] == [] and out["interesting"] == []


def test_parse_bucket_listing_decodes_xml_escaped_keys():
    """The listing is XML, so `R&D.sql` arrives as `R&amp;D.sql`. Keeping the
    escaped text would percent-encode the escape itself into the link
    (`R%26amp%3BD.sql` — a 404), print the wrong key as evidence, and run the
    interesting-key regex against text the bucket doesn't actually contain."""
    body = ("<ListBucketResult>"
            "<Contents><Key>R&amp;D.sql</Key><Size>10</Size></Contents>"
            "</ListBucketResult>")
    out = intel._parse_bucket_listing("s3", "acme", body)
    obj = out["objects"][0]
    assert obj["key"] == "R&D.sql"                       # decoded evidence
    assert obj["url"] == "https://acme.s3.amazonaws.com/R%26D.sql"
    assert "amp" not in obj["url"]                       # the escape is gone, not encoded
    assert obj["interesting"] is True                    # .sql still classified


def test_parse_bucket_listing_decodes_entities_without_double_decoding():
    """All five XML entities plus numeric forms decode; an already-plain key is
    untouched; and a key whose real name contains `&amp;` decodes exactly one
    level (`&amp;amp;` -> `&amp;`), never two."""
    body = ("<ListBucketResult>"
            "<Contents><Key>a&lt;b&gt;c.env</Key></Contents>"
            "<Contents><Key>say&quot;hi&quot;.bak</Key></Contents>"
            "<Contents><Key>it&#39;s&#32;mine.sql</Key></Contents>"
            "<Contents><Key>literal&amp;amp;entity.ini</Key></Contents>"
            "<Contents><Key>plain-file.yml</Key></Contents>"
            "</ListBucketResult>")
    keys = [o["key"] for o in intel._parse_bucket_listing("s3", "acme", body)["objects"]]
    assert keys == ["a<b>c.env", 'say"hi".bak', "it's mine.sql",
                    "literal&amp;entity.ini", "plain-file.yml"]


def test_parse_bucket_listing_decodes_azure_name_keys():
    """Azure's <Name> path shares the decode — same escaping, same consequence."""
    body = ("<EnumerationResults><Blobs><Blob><Name>Q&amp;A/id_rsa</Name>"
            "<Properties><Content-Length>1675</Content-Length></Properties>"
            "</Blob></Blobs></EnumerationResults>")
    obj = intel._parse_bucket_listing("azure", "acme", body)["objects"][0]
    assert obj["key"] == "Q&A/id_rsa"
    assert obj["url"] == "https://acme.blob.core.windows.net/Q%26A/id_rsa"
    assert obj["interesting"] is True


def test_parse_bucket_listing_entity_can_hide_a_sensitive_suffix():
    """Regression for the classification half of the bug: with the escape left in
    place, `&#46;` masks the extension and the key reads as benign."""
    body = ("<ListBucketResult><Contents><Key>prod&#46;sql</Key></Contents>"
            "</ListBucketResult>")
    out = intel._parse_bucket_listing("s3", "acme", body)
    assert out["objects"][0]["key"] == "prod.sql"
    assert [o["key"] for o in out["interesting"]] == ["prod.sql"]


def test_bucket_object_url_per_provider_and_quoting():
    assert intel._bucket_object_url("s3", "acme", "a/b.txt") == \
        "https://acme.s3.amazonaws.com/a/b.txt"
    assert intel._bucket_object_url("gcs", "acme", "a/b.txt") == \
        "https://storage.googleapis.com/acme/a/b.txt"
    assert intel._bucket_object_url("azure", "acme", "a/b.txt") == \
        "https://acme.blob.core.windows.net/a/b.txt"
    # spaces must be escaped so the link is usable
    assert "%20" in intel._bucket_object_url("s3", "acme", "my file.txt")


async def test_bucket_enum_attaches_objects_for_public_and_not_for_403():
    async def fake_get(url, timeout=None):
        if url.startswith("https://acme.s3.amazonaws.com"):
            return _FakeRespText(200, _S3_LISTING)
        return _FakeRespText(403, "denied")
    client = type("C", (), {"get": staticmethod(fake_get)})()
    out = await intel.bucket_enum(client, ["acme"])
    public = [b for b in out if b["public"]]
    private = [b for b in out if not b["public"]]
    assert public and public[0]["object_count"] == 3
    assert any(o["key"] == ".env" for o in public[0]["interesting"])
    # non-public entries keep the original shape — no object fields bolted on
    assert private and "objects" not in private[0]


def test_summarize_entry_points_public_bucket_lists_sensitive_objects():
    buckets = [{"name": "acme", "provider": "s3", "url": "https://acme.s3.amazonaws.com",
                "status": 200, "public": True, "object_count": 3, "truncated": False,
                "interesting": [{"key": ".env", "url": "u", "size": 5, "interesting": True}],
                "objects": []}]
    eps = intel.summarize_entry_points([], {}, buckets, {}, [], [])
    assert len(eps) == 1
    ep = eps[0]
    assert ep["type"] == "public-bucket"
    assert ep["severity"] == "critical"          # sensitive objects present
    assert "3 object(s)" in ep["summary"] and ".env" in ep["summary"]


def test_summarize_entry_points_public_bucket_without_objects_stays_high():
    buckets = [{"name": "acme", "provider": "s3", "url": "u", "status": 200, "public": True}]
    eps = intel.summarize_entry_points([], {}, buckets, {}, [], [])
    assert eps[0]["severity"] == "high"          # backward compatible, no object data


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


# --------------------------------------------------------------------------- #
# Classic WHOIS (port 43) fallback — for TLDs with no RDAP service at all
# --------------------------------------------------------------------------- #
class _FakeWhoisReader:
    """Fake asyncio StreamReader — serves canned bytes, naturally exhausting
    (returns b"") once consumed, so both .read(-1) (whole buffer) and
    chunked .read(n) call patterns terminate correctly."""
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def read(self, n=-1):
        if self._pos >= len(self._data):
            return b""
        end = len(self._data) if n == -1 else self._pos + n
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk


class _FakeWhoisWriter:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data):
        self.written += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True


_REAL_IO_WHOIS_SAMPLE = """Domain Name: nic.io
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.identitydigital.services
Registrar URL: https://identity.digital
Updated Date: 2024-09-23T15:51:12Z
Creation Date: 2003-09-15T11:13:53Z
Registry Expiry Date: 2027-05-01T00:00:02Z
Registrar: Registry Operator acts as Registrar (9999)
Registrar IANA ID: 9999
Registrar Abuse Contact Email: abuse@identity.digital
Registrar Abuse Contact Phone: +1.6664447777
Domain Status: serverDeleteProhibited
Domain Status: serverTransferProhibited
Domain Status: serverUpdateProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
"""

_RIPE_STYLE_WHOIS_SAMPLE = """% This is a RIPE-style whois server.
domain: example.fr
status: active
registrar: Example Registrar SAS
Expiry Date: 2027-03-01T00:00:00Z
created: 2015-03-01T00:00:00Z
last-update: 2025-01-01T00:00:00Z
nserver: ns1.example.fr
nserver: ns2.example.fr
Registrant Organization: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
"""


def test_parse_whois43_extracts_real_captured_io_registry_format():
    # captured from a real .io registry WHOIS response — regression-guards
    # against "Registrar WHOIS Server:"/"Registrar Abuse..."/etc. false-
    # matching the "registrar:" pattern (re.match anchors at line start,
    # so only a line literally starting with "Registrar:" matches).
    out = intel._parse_whois43(_REAL_IO_WHOIS_SAMPLE)
    assert out["registrar"] == "Registry Operator acts as Registrar (9999)"
    assert out["created"] == "2003-09-15T11:13:53Z"
    assert out["expires"] == "2027-05-01T00:00:02Z"
    assert out["last_changed"] == "2024-09-23T15:51:12Z"
    assert out["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert out["status"] == ["serverDeleteProhibited", "serverTransferProhibited",
                             "serverUpdateProhibited"]


def test_parse_whois43_ripe_style_lowercase_labels_and_privacy_redaction():
    out = intel._parse_whois43(_RIPE_STYLE_WHOIS_SAMPLE)
    assert out["registrar"] == "Example Registrar SAS"
    assert out["created"] == "2015-03-01T00:00:00Z"
    assert out["expires"] == "2027-03-01T00:00:00Z"
    assert out["last_changed"] == "2025-01-01T00:00:00Z"
    assert out["nameservers"] == ["ns1.example.fr", "ns2.example.fr"]
    assert out["privacy_protected"] is True
    assert out["registrant_org"] == "REDACTED FOR PRIVACY"


def test_parse_whois43_empty_text_returns_default_shape():
    assert intel._parse_whois43("") == intel.empty_whois_entry()
    assert intel._parse_whois43(None) == intel.empty_whois_entry()


async def test_iana_whois_referral_extracts_server(monkeypatch):
    reader = _FakeWhoisReader(b"whois: whois.identitydigital.services\r\nstatus: active\r\n")
    writer = _FakeWhoisWriter()

    async def fake_open_connection(host, port):
        assert host == "whois.iana.org" and port == 43
        return reader, writer
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    server = await intel._iana_whois_referral("io")
    assert server == "whois.identitydigital.services"
    assert writer.written == b"io\r\n"
    assert writer.closed is True


async def test_iana_whois_referral_returns_none_when_no_whois_line(monkeypatch):
    async def fake_open_connection(host, port):
        return _FakeWhoisReader(b"status: legacy\r\n"), _FakeWhoisWriter()
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    assert await intel._iana_whois_referral("zz") is None


async def test_iana_whois_referral_returns_none_on_connection_failure(monkeypatch):
    async def fake_open_connection(host, port):
        raise OSError("network unreachable")
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    assert await intel._iana_whois_referral("io") is None


async def test_whois43_query_sends_domain_and_accumulates_chunks(monkeypatch):
    reader = _FakeWhoisReader(b"Domain Name: X.IO\r\nRegistrar: Test\r\n")
    writer = _FakeWhoisWriter()

    async def fake_open_connection(host, port):
        assert host == "whois.example.io" and port == 43
        return reader, writer
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    text = await intel._whois43_query("whois.example.io", "x.io")
    assert "Registrar: Test" in text
    assert writer.written == b"x.io\r\n"
    assert writer.closed is True


async def test_whois43_query_returns_none_on_failure(monkeypatch):
    async def fake_open_connection(host, port):
        raise OSError("connection refused")
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    assert await intel._whois43_query("whois.example.io", "x.io") is None


async def test_whois43_lookup_full_flow(monkeypatch):
    async def fake_referral(tld):
        assert tld == "io"
        return "whois.identitydigital.services"

    async def fake_query(server, domain):
        assert server == "whois.identitydigital.services" and domain == "x.io"
        return "Registrar: Test Registrar\r\nCreation Date: 2020-01-01T00:00:00Z\r\n"
    monkeypatch.setattr(intel, "_iana_whois_referral", fake_referral)
    monkeypatch.setattr(intel, "_whois43_query", fake_query)

    out = await intel.whois43_lookup("x.io")
    assert out["registrar"] == "Test Registrar"


async def test_whois43_lookup_empty_when_no_referral(monkeypatch):
    async def fake_referral(tld):
        return None
    monkeypatch.setattr(intel, "_iana_whois_referral", fake_referral)
    assert await intel.whois43_lookup("x.zz") == {}


async def test_whois43_lookup_empty_when_nothing_useful_parsed(monkeypatch):
    async def fake_referral(tld):
        return "whois.example"

    async def fake_query(server, domain):
        return "% no useful data here\r\n"
    monkeypatch.setattr(intel, "_iana_whois_referral", fake_referral)
    monkeypatch.setattr(intel, "_whois43_query", fake_query)
    assert await intel.whois43_lookup("x.zz") == {}


async def test_whois_lookup_uses_rdap_only_when_registrar_present(monkeypatch):
    async def fake_rdap(client, domain):
        return {**intel.empty_whois_entry(), "registrar": "RDAP Registrar"}
    called = []

    async def fake_whois43(domain):
        called.append(domain)
        return {}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    out = await intel.whois_lookup(None, "x.com")
    assert out["registrar"] == "RDAP Registrar"
    assert out["source"] == "rdap"
    assert called == []                      # whois43 not needed, never called


async def test_whois_lookup_falls_back_to_whois43_when_rdap_empty(monkeypatch):
    async def fake_rdap(client, domain):
        return {}

    async def fake_whois43(domain):
        return {**intel.empty_whois_entry(), "registrar": "WHOIS43 Registrar"}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    out = await intel.whois_lookup(None, "x.io")
    assert out["registrar"] == "WHOIS43 Registrar"
    assert out["source"] == "whois43"


async def test_whois_lookup_merges_rdap_and_whois43_preferring_rdap_values(monkeypatch):
    # RDAP has dates/nameservers but no registrar; whois43 fills registrar
    # only — RDAP's existing values must not be clobbered by whois43's.
    async def fake_rdap(client, domain):
        return {**intel.empty_whois_entry(), "created": "2020-01-01T00:00:00Z",
               "nameservers": ["ns1.x.com"]}

    async def fake_whois43(domain):
        return {**intel.empty_whois_entry(), "registrar": "WHOIS43 Registrar",
               "created": "SHOULD-NOT-OVERRIDE-RDAP"}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    out = await intel.whois_lookup(None, "x.com")
    assert out["registrar"] == "WHOIS43 Registrar"
    assert out["created"] == "2020-01-01T00:00:00Z"
    assert out["nameservers"] == ["ns1.x.com"]
    assert out["source"] == "rdap+whois43"


async def test_whois_lookup_empty_entry_with_none_source_when_both_fail(monkeypatch):
    async def fake_rdap(client, domain):
        return {}

    async def fake_whois43(domain):
        return {}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    out = await intel.whois_lookup(None, "x.zz")
    assert out["registrar"] is None
    assert out["source"] is None


async def test_whois_lookup_falls_back_to_vt_whois_when_rdap_and_whois43_both_empty(monkeypatch):
    # The scenario that motivated this tier: raw TCP/port 43 is blocked
    # outright in some sandboxed execution environments, so whois43_lookup
    # comes back empty no matter the TLD — VT's own HTTPS-fetched mirror
    # is the only remaining source that can actually reach the network.
    async def fake_rdap(client, domain):
        return {}

    async def fake_whois43(domain):
        return {}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    vt_text = "Domain Name: X.IO\r\nRegistrar: VT-Sourced Registrar\r\nCreation Date: 2015-05-05T00:00:00Z\r\n"
    out = await intel.whois_lookup(None, "x.io", vt_whois_text=vt_text)
    assert out["registrar"] == "VT-Sourced Registrar"
    assert out["created"] == "2015-05-05T00:00:00Z"
    assert out["source"] == "vt-whois"


async def test_whois_lookup_vt_whois_not_consulted_when_whois43_already_found_registrar(monkeypatch):
    async def fake_rdap(client, domain):
        return {}

    async def fake_whois43(domain):
        return {**intel.empty_whois_entry(), "registrar": "WHOIS43 Registrar"}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    vt_text = "Registrar: Should Not Be Used\r\n"
    out = await intel.whois_lookup(None, "x.io", vt_whois_text=vt_text)
    assert out["registrar"] == "WHOIS43 Registrar"
    assert out["source"] == "whois43"


async def test_whois_lookup_vt_whois_ignored_when_it_parses_to_nothing_useful(monkeypatch):
    async def fake_rdap(client, domain):
        return {}

    async def fake_whois43(domain):
        return {}
    monkeypatch.setattr(intel, "rdap_lookup", fake_rdap)
    monkeypatch.setattr(intel, "whois43_lookup", fake_whois43)

    out = await intel.whois_lookup(None, "x.zz", vt_whois_text="% no useful fields in here\r\n")
    assert out["registrar"] is None
    assert out["source"] is None


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


# --------------------------------------------------------------------------- #
# Email security posture — full SPF/DKIM/DMARC records + parsed analysis
# --------------------------------------------------------------------------- #
def test_parse_spf_extracts_mechanisms_and_qualifier():
    sp = intel.parse_spf("v=spf1 include:_spf.google.com ip4:1.2.3.0/24 a mx ~all")
    assert sp["all_qualifier"] == "~"
    assert sp["includes"] == ["_spf.google.com"]
    assert sp["ip4"] == ["1.2.3.0/24"]
    # include + a + mx each cost a DNS lookup; ip4 and all do not
    assert sp["lookup_count"] == 3
    assert sp["exceeds_lookup_limit"] is False


def test_parse_spf_flags_lookup_limit_overflow_and_ptr():
    rec = "v=spf1 " + " ".join(f"include:s{i}.test" for i in range(11)) + " ptr -all"
    sp = intel.parse_spf(rec)
    assert sp["lookup_count"] > intel.SPF_MAX_LOOKUPS
    assert sp["exceeds_lookup_limit"] is True
    assert sp["ptr"] is True
    assert sp["all_qualifier"] == "-"


def test_parse_spf_handles_none_and_redirect():
    assert intel.parse_spf(None)["mechanisms"] == []
    assert intel.parse_spf("v=spf1 redirect=_spf.other.test")["redirect"] == "_spf.other.test"


def test_parse_dmarc_tag_values():
    dp = intel.parse_dmarc("v=DMARC1; p=reject; sp=none; pct=50; "
                           "rua=mailto:a@x.test,mailto:b@x.test; adkim=s")
    assert dp["p"] == "reject" and dp["sp"] == "none"
    assert dp["pct"] == 50
    assert dp["rua"] == ["mailto:a@x.test", "mailto:b@x.test"]
    assert dp["adkim"] == "s"
    assert intel.parse_dmarc(None)["p"] is None


async def test_email_security_keeps_full_records_and_dkim_selector(monkeypatch):
    spf = "v=spf1 include:_spf.google.com ~all"
    dmarc = "v=DMARC1; p=reject; rua=mailto:d@x.test"
    dkim = "v=DKIM1; k=rsa; p=MIIBIjANBg"
    answers = {
        ("x.test", "TXT"): [_FakeTXTRecord(spf)],
        # The include must resolve for the lookup budget to be a complete count;
        # an unresolvable include is a separate case, covered by its own test.
        ("_spf.google.com", "TXT"): [_FakeTXTRecord("v=spf1 ip4:1.2.3.0/24 -all")],
        ("_dmarc.x.test", "TXT"): [_FakeTXTRecord(dmarc)],
        ("google._domainkey.x.test", "TXT"): [_FakeTXTRecord(dkim)],
    }
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))
    out = await intel.email_security("x.test", None)
    # Verbatim records must survive to the report, not just a grade.
    assert out["spf"] == spf
    assert out["dmarc"] == dmarc
    assert out["dkim"] is True
    assert out["dkim_selector"] == "google"      # names which selector matched
    assert out["dkim_record"] == dkim
    assert out["spf_parsed"]["includes"] == ["_spf.google.com"]
    # 1 lookup for the include; the target adds none, so the budget is clean.
    assert out["spf_parsed"]["lookup_count"] == 1
    assert out["spf_parsed"]["lookup_count_complete"] is True
    assert out["dmarc_parsed"]["p"] == "reject"
    assert out["grade"] == "PASS" and out["issues"] == []


def test_parse_spf_marks_its_lookup_count_incomplete_when_the_record_delegates():
    """parse_spf is deliberately I/O-free, so its count covers only the apex
    record. That is the complete figure when nothing delegates, and a lower bound
    the moment an include:/redirect= appears — the flag says which."""
    sp = intel.parse_spf("v=spf1 a mx ip4:1.2.3.4 -all")
    assert sp["lookup_count"] == 2
    assert sp["lookup_count_complete"] is True           # nothing to expand
    sp = intel.parse_spf("v=spf1 include:x.test -all")
    assert sp["top_level_lookup_count"] == 1
    assert sp["lookup_count_complete"] is False          # include: not expanded
    assert intel.parse_spf("v=spf1 redirect=y.test")["lookup_count_complete"] is False


def _spf_zone_txt(zone, fail=(), calls=None):
    """Stand-in for email_security's TXT helper: (records, failed) per name."""
    async def txt(name):
        norm = name.lower().rstrip(".")
        if calls is not None:
            calls.append(norm)
        if norm in fail:
            return [], True
        rec = zone.get(norm)
        return ([rec] if rec else []), False
    return txt


# Top-level costs 2 lookups; expansion costs 12 — the shape of a real permerror.
_SPF_OVERFLOW_ZONE = {
    "b.test": "v=spf1 a mx include:d.test -all",         # 3
    "c.test": "v=spf1 a mx exists:e.test -all",          # 3
    "d.test": "v=spf1 a mx a:m1.test a:m2.test -all",    # 4
}
_SPF_OVERFLOW_ROOT = "v=spf1 include:b.test include:c.test -all"


async def test_spf_lookup_count_expands_includes_past_the_limit():
    """The finding this exists for: a record that looks compliant at the top level
    but blows RFC 7208 §4.6.4's budget once includes are evaluated."""
    assert intel.parse_spf(_SPF_OVERFLOW_ROOT)["lookup_count"] == 2   # under 10 alone
    count, complete, exceeded = await intel.spf_lookup_count(
        _SPF_OVERFLOW_ROOT, _spf_zone_txt(_SPF_OVERFLOW_ZONE))
    assert exceeded is True
    assert count > intel.SPF_MAX_LOOKUPS


async def test_spf_lookup_count_counts_a_compliant_tree_exactly():
    zone = {"b.test": "v=spf1 a mx -all"}                # 2
    count, complete, exceeded = await intel.spf_lookup_count(
        "v=spf1 include:b.test ip4:1.2.3.4 -all", _spf_zone_txt(zone))
    assert (count, complete, exceeded) == (3, True, False)   # 1 include + a + mx


async def test_spf_lookup_count_terminates_on_an_include_cycle():
    """A self-referential include must end, not loop: every hop costs a counted
    lookup, so the budget check is what bounds the walk. The per-domain cache also
    keeps it to a single DNS query."""
    calls = []
    zone = {"a.test": "v=spf1 include:a.test -all"}
    count, complete, exceeded = await intel.spf_lookup_count(
        zone["a.test"], _spf_zone_txt(zone, calls=calls))
    assert exceeded is True
    assert count <= intel.SPF_MAX_LOOKUPS + 1            # stopped as soon as it passed
    assert calls == ["a.test"]                           # cached, queried once


async def test_spf_lookup_count_stops_querying_once_over_the_limit():
    """Expansion must not fan out through a pathological record: once the count
    passes the cap the verdict is settled, so the walk stops."""
    calls = []
    zone = {f"s{i}.test": "v=spf1 " + " ".join(f"include:n{i}{j}.test" for j in range(9))
            for i in range(9)}
    zone.update({f"n{i}{j}.test": "v=spf1 a mx -all" for i in range(9) for j in range(9)})
    root = "v=spf1 " + " ".join(f"include:s{i}.test" for i in range(9))
    count, complete, exceeded = await intel.spf_lookup_count(root, _spf_zone_txt(zone, calls=calls))
    assert exceeded is True
    # Every queued target came from a counted lookup, so queries stay bounded by
    # the budget rather than by the size of the tree (81+ records here).
    assert len(calls) <= intel.SPF_MAX_LOOKUPS + 1


async def test_spf_lookup_count_reports_incomplete_rather_than_guessing():
    """A failed lookup inside an include must not be silently treated as zero
    further lookups — that would claim compliance we cannot verify."""
    zone = {"b.test": "v=spf1 a mx -all"}
    count, complete, exceeded = await intel.spf_lookup_count(
        "v=spf1 include:b.test include:gone.test -all",
        _spf_zone_txt(zone, fail={"gone.test"}))
    assert complete is False
    assert exceeded is False                             # not confirmed over the limit
    assert count == 4                                    # 2 includes + a + mx


async def test_spf_lookup_count_handles_missing_target_record_and_no_spf():
    """An include: pointing at a domain with no SPF is a permerror in its own
    right, but the lookup still counted and there is nothing to expand."""
    count, complete, exceeded = await intel.spf_lookup_count(
        "v=spf1 include:empty.test -all", _spf_zone_txt({}))
    assert (count, complete, exceeded) == (1, True, False)
    assert await intel.spf_lookup_count(None, _spf_zone_txt({})) == (0, True, False)


async def test_spf_lookup_count_follows_redirect():
    zone = {"r.test": "v=spf1 a mx a:x.test -all"}        # 3, plus the redirect itself
    count, complete, exceeded = await intel.spf_lookup_count(
        "v=spf1 redirect=r.test", _spf_zone_txt(zone))
    assert (count, complete, exceeded) == (4, True, False)


async def test_email_security_expands_spf_includes_for_the_lookup_limit(monkeypatch):
    """End-to-end: the report's count and verdict come from the expanded tree, so
    a real permerror is reported instead of a compliant-looking 2/10."""
    answers = {
        ("x.test", "TXT"): [_FakeTXTRecord(_SPF_OVERFLOW_ROOT)],
        ("_dmarc.x.test", "TXT"): [_FakeTXTRecord("v=DMARC1; p=reject; rua=mailto:d@x.test")],
        ("default._domainkey.x.test", "TXT"): [_FakeTXTRecord("v=DKIM1; p=k")],
    }
    answers.update({(name, "TXT"): [_FakeTXTRecord(rec)]
                    for name, rec in _SPF_OVERFLOW_ZONE.items()})
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))
    out = await intel.email_security("x.test", None)
    sp = out["spf_parsed"]
    assert sp["top_level_lookup_count"] == 2             # what the apex alone shows
    assert sp["lookup_count"] > intel.SPF_MAX_LOOKUPS    # what a receiver spends
    assert sp["exceeds_lookup_limit"] is True
    joined = " | ".join(out["issues"])
    assert "exceeds" in joined and "includes expanded" in joined
    assert out["grade"] == "FAIL"                        # permerror is a risk


async def test_email_security_does_not_claim_compliance_on_an_incomplete_count(monkeypatch):
    """When an include's lookup fails the count is a lower bound; the report must
    say so rather than presenting it as a clean n/10."""
    answers = {
        ("x.test", "TXT"): [_FakeTXTRecord("v=spf1 include:gone.test -all")],
        ("_dmarc.x.test", "TXT"): [_FakeTXTRecord("v=DMARC1; p=reject; rua=mailto:d@x.test")],
        ("default._domainkey.x.test", "TXT"): [_FakeTXTRecord("v=DKIM1; p=k")],
    }
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))
    out = await intel.email_security("x.test", None)
    assert out["spf_parsed"]["lookup_count_complete"] is False
    assert out["spf_parsed"]["exceeds_lookup_limit"] is False   # no false accusation
    assert any("incomplete" in i for i in out["issues"])
    assert out["grade"] != "PASS"


async def test_email_security_flags_pct_sp_and_missing_rua(monkeypatch):
    answers = {
        ("x.test", "TXT"): [_FakeTXTRecord("v=spf1 -all")],
        ("_dmarc.x.test", "TXT"): [_FakeTXTRecord("v=DMARC1; p=reject; sp=none; pct=20")],
        ("default._domainkey.x.test", "TXT"): [_FakeTXTRecord("v=DKIM1; p=k")],
    }
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _FakeDNSResolver(answers))
    out = await intel.email_security("x.test", None)
    joined = " | ".join(out["issues"])
    assert "pct=20" in joined
    assert "sp=none" in joined
    assert "rua=" in joined


class NXDOMAIN(Exception):
    """Stands in for dns.resolver.NXDOMAIN — matched by class name."""


class NoAnswer(Exception):
    """Stands in for dns.resolver.NoAnswer — matched by class name."""


class _CnameTargetResolver:
    """Resolver for cname_target_status: names in `live` answer, names in
    `missing` raise NXDOMAIN, names in `noanswer` exist without an address, and
    anything else fails with a transport error (inconclusive)."""
    def __init__(self, live=(), missing=(), noanswer=()):
        self.live, self.missing, self.noanswer = set(live), set(missing), set(noanswer)

    async def resolve(self, name, rtype, **kwargs):
        if name in self.missing:
            raise NXDOMAIN(name)
        if name in self.noanswer:
            raise NoAnswer(name)
        if name in self.live:
            return ["1.2.3.4"] if rtype == "A" else ["::1"]
        raise Exception(f"timeout for {name} {rtype}")


async def test_cname_target_status_distinguishes_missing_live_and_inconclusive(monkeypatch):
    """NXDOMAIN on the target is the takeover signal; a resolvable target is not
    a finding; and a timeout must stay inconclusive rather than being reported."""
    monkeypatch.setattr(sources, "get_resolver", lambda ns: _CnameTargetResolver(
        live=["ok.example.net"], missing=["gone.example.net"],
        noanswer=["exists.example.net"]))
    assert await sources.cname_target_status("gone.example.net", None) == "nxdomain"
    assert await sources.cname_target_status("ok.example.net", None) == "resolves"
    # The name exists, just carries no address — not a dangling target.
    assert await sources.cname_target_status("exists.example.net", None) == "resolves"
    assert await sources.cname_target_status("slow.example.net", None) == "unknown"
    assert await sources.cname_target_status("", None) == "unknown"


def test_mark_dangling_cname_flags_only_nxdomain():
    """"resolves" and "unknown" must never become client-facing findings."""
    for status in ("resolves", "unknown"):
        h = Host("dev.x.com", cname="gone.example.net")
        active.mark_dangling_cname(h, status)
        assert h.takeover is None and h.takeover_confidence is None
    h = Host("dev.x.com", cname="gone.example.net")
    active.mark_dangling_cname(h, "nxdomain")
    assert h.takeover_confidence == "confirmed"
    assert "NXDOMAIN" in h.takeover


def test_mark_dangling_cname_works_for_providers_with_no_signature():
    """The whole point of the NXDOMAIN path: it doesn't need TAKEOVER_SIGS, so it
    catches providers nobody has written a signature for."""
    unknown = "abandoned.some-saas-nobody-signatured.io"
    assert not any(sig in unknown for sig in intel.TAKEOVER_SIGS)
    h = Host("dev.x.com", cname=unknown)
    active.mark_dangling_cname(h, "nxdomain")
    assert h.takeover_confidence == "confirmed"
    assert unknown in h.takeover
    # A recognized provider is still named when one matches.
    h2 = Host("dev.x.com", cname="dev.x.com.s3.amazonaws.com")
    active.mark_dangling_cname(h2, "nxdomain")
    assert "s3.amazonaws.com" in h2.takeover


def test_mark_dangling_cname_does_not_overwrite_a_signature_finding():
    """A body-signature hit already carries corroborating evidence."""
    h = Host("dev.x.com", cname="dev.x.com.s3.amazonaws.com",
             takeover="Dangling CNAME -> ... unclaimed-service signature matched",
             takeover_confidence="likely")
    active.mark_dangling_cname(h, "nxdomain")
    assert h.takeover_confidence == "likely"


def test_check_takeover_sets_confidence_for_both_signature_paths():
    body_hit = Host("a.x.com", cname="a.x.com.s3.amazonaws.com")
    active._check_takeover(body_hit, "<html>nosuchbucket</html>")
    assert body_hit.takeover_confidence == "likely"
    no_body = Host("b.x.com", cname="b.x.com.s3.amazonaws.com")
    active._check_takeover(no_body, "<html>a normal page</html>")
    assert no_body.takeover_confidence == "possible"


def test_entry_point_takeover_severity_comes_from_confidence_not_text():
    """Regression for the old phrase-match on the summary string."""
    cf = {"detected": False, "candidates": {}}
    sev = {}
    for conf in ("confirmed", "likely", "possible"):
        h = Host("a.x.com", cname="c", takeover="wording that says nothing",
                 takeover_confidence=conf)
        eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
        sev[conf] = eps[0]["severity"]
        assert eps[0]["confidence"] == conf
    assert sev == {"confirmed": "critical", "likely": "critical", "possible": "high"}


class _AbsentRecordResolver:
    """Every name resolves to a definitive 'nothing published' answer."""
    async def resolve(self, name, rtype, **kwargs):
        raise NoAnswer(f"no {rtype} for {name}")


class _BrokenResolver:
    """Every lookup fails with a transport error (timeout/servfail), counting
    calls so the TCP retry can be observed."""
    def __init__(self):
        self.calls = []

    async def resolve(self, name, rtype, **kwargs):
        self.calls.append((name, rtype, kwargs.get("tcp", False)))
        raise Exception("LifetimeTimeout")


async def test_email_security_absent_records_fail_and_list_selectors(monkeypatch):
    """A definitive NoAnswer means the records really aren't published — that is
    a genuine FAIL, distinct from a lookup that errored out."""
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _AbsentRecordResolver())
    out = await intel.email_security("x.test", None)
    assert out["grade"] == "FAIL"
    assert out["spf"] is None and out["dmarc"] is None and out["dkim"] is False
    assert out["dkim_selector"] is None
    assert out["lookup_errors"] == []                     # nothing failed, records absent
    joined = " | ".join(out["issues"])
    assert "No SPF record" in joined and "No DMARC record" in joined
    # the selectors actually probed are recorded so "inconclusive" is explicit
    assert out["dkim_selectors_checked"] == list(intel.DKIM_SELECTORS)


async def test_email_security_failed_lookup_is_inconclusive_not_a_missing_record(monkeypatch):
    """A DNS timeout must NOT be reported as 'No SPF record' — that would put a
    false finding in a client deliverable. It is inconclusive instead."""
    broken = _BrokenResolver()
    monkeypatch.setattr(intel, "get_resolver", lambda ns: broken)
    out = await intel.email_security("x.test", None)
    joined = " | ".join(out["issues"])
    assert "SPF lookup failed (inconclusive" in joined
    assert "DMARC lookup failed (inconclusive" in joined
    assert "No SPF record" not in joined and "No DMARC record" not in joined
    assert out["lookup_errors"]                           # the failure is recorded
    assert out["grade"] != "FAIL"                         # not a confirmed failure
    # Apex TXT is retried over TCP — a large real-world TXT set exceeds UDP's
    # 512 bytes and SPF is exactly what goes missing on truncation.
    assert ("x.test", "TXT", True) in broken.calls


async def test_email_security_nxdomain_not_retried_over_tcp(monkeypatch):
    """NXDOMAIN/NoAnswer are real answers — retrying them over TCP is wasted
    queries against every DKIM selector."""
    class _Counting(_AbsentRecordResolver):
        def __init__(self):
            self.calls = []
        async def resolve(self, name, rtype, **kwargs):
            self.calls.append(kwargs.get("tcp", False))
            raise NXDOMAIN("nope")
    r = _Counting()
    monkeypatch.setattr(intel, "get_resolver", lambda ns: r)
    await intel.email_security("x.test", None)
    assert all(tcp is False for tcp in r.calls)


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
# Live TLS certificate inspection
# --------------------------------------------------------------------------- #
from lrecon import tlsinfo

crypto = pytest.importorskip("cryptography", reason="optional [tls] extra")


def _make_cert(cn="www.x.com", sans=("www.x.com", "api.x.com"), days=30,
               issuer_cn=None, not_before_days=1):
    """A DER certificate to parse — no network, no fixtures on disk."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = _make_cert._key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn \
        else x509.Name([])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]) \
        if issuer_cn else subject
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=not_before_days))
               .not_valid_after(now + datetime.timedelta(days=days)))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_make_cert._key = _cert_key()          # generated once; RSA keygen is slow


def test_parse_cert_extracts_names_issuer_and_validity():
    c = tlsinfo.parse_cert(_make_cert(cn="www.x.com",
                                      sans=("www.x.com", "api.x.com", "*.dev.x.com"),
                                      issuer_cn="Some CA"))
    assert c["cn"] == "www.x.com"
    assert c["sans"] == ["*.dev.x.com", "api.x.com", "www.x.com"]   # sorted, lowercased
    assert c["issuer"] == "some ca"
    assert c["expired"] is False and c["not_yet_valid"] is False
    assert c["self_signed"] is False
    assert 25 <= c["days_to_expiry"] <= 30


def test_parse_cert_flags_self_signed_and_expired():
    self_signed = tlsinfo.parse_cert(_make_cert(issuer_cn=None))
    assert self_signed["self_signed"] is True
    # not_valid_after in the past: negative `days` puts expiry before now.
    expired = tlsinfo.parse_cert(_make_cert(days=-5, not_before_days=30))
    assert expired["expired"] is True
    assert expired["days_to_expiry"] < 0


def test_parse_cert_tolerates_no_san_and_no_cn():
    no_san = tlsinfo.parse_cert(_make_cert(sans=()))
    assert no_san["sans"] == [] and no_san["cn"] == "www.x.com"
    no_cn = tlsinfo.parse_cert(_make_cert(cn=None, sans=("only.x.com",)))
    assert no_cn["cn"] is None and no_cn["sans"] == ["only.x.com"]


def test_parse_cert_malformed_returns_none_not_raises():
    assert tlsinfo.parse_cert(b"not a certificate") is None
    assert tlsinfo.parse_cert(b"") is None


def test_cert_names_folds_in_the_cn():
    """Older/internal CAs still put the only name in the CN."""
    assert tlsinfo.cert_names({"cn": "only.x.com", "sans": []}) == ["only.x.com"]
    both = tlsinfo.cert_names({"cn": "a.x.com", "sans": ["b.x.com"]})
    assert set(both) == {"a.x.com", "b.x.com"}
    assert tlsinfo.cert_names(None) == []


def test_cert_matches_scope_accepts_apex_subdomain_and_wildcard():
    assert tlsinfo.cert_matches_scope({"cn": None, "sans": ["x.com"]}, ["x.com"]) == "x.com"
    assert tlsinfo.cert_matches_scope({"cn": None, "sans": ["a.x.com"]}, ["x.com"]) == "a.x.com"
    assert tlsinfo.cert_matches_scope({"cn": None, "sans": ["*.x.com"]}, ["x.com"]) == "*.x.com"
    # A lookalike domain must not count as in scope.
    assert tlsinfo.cert_matches_scope({"cn": None, "sans": ["notx.com"]}, ["x.com"]) is None
    assert tlsinfo.cert_matches_scope({"cn": None, "sans": ["x.com.evil.net"]},
                                      ["x.com"]) is None


def test_in_scope_cert_names_drops_wildcards_and_other_tenants():
    """A shared/CDN cert carries other tenants' domains — those are not the
    client's assets. Wildcards aren't resolvable hosts, so they're dropped too."""
    cert = {"cn": "www.x.com",
            "sans": ["www.x.com", "api.x.com", "*.dev.x.com", "other-tenant.net"]}
    assert tlsinfo.in_scope_cert_names(cert, ["x.com"]) == ["api.x.com", "www.x.com"]


async def test_fetch_cert_returns_none_when_unreachable():
    """An unreachable or non-TLS peer must not raise into the scan."""
    assert await tlsinfo.fetch_cert("127.0.0.1", port=1, timeout=0.5) is None


async def test_fetch_cert_skips_cleanly_without_cryptography(monkeypatch):
    monkeypatch.setattr(tlsinfo, "HAVE_CRYPTO", False)
    assert await tlsinfo.fetch_cert("example.com") is None
    assert tlsinfo.parse_cert(_make_cert()) is None


def test_tls_sni_omitted_for_bare_ip():
    """SNI carries a hostname; sending an IP literal is invalid. Origin discovery
    depends on seeing the default cert an IP serves."""
    assert tlsinfo._is_ip("192.0.2.1") is True
    assert tlsinfo._is_ip("2001:db8::1") is True
    assert tlsinfo._is_ip("example.com") is False


async def test_cloudflare_origin_confirmed_by_cert_without_http_probe(monkeypatch):
    """A cert naming the target is stronger evidence than the Server header, and
    settles it without sending a request past the handshake."""
    monkeypatch.setattr(intel, "fetch_cert", _fake_fetch_cert(
        {"9.9.9.9": {"cn": "www.x.com", "sans": ["www.x.com"], "issuer": "Some CA"}}))
    probe = _RecordingProbeClient()
    hosts = {"a.x.com": Host("a.x.com", ips=["9.9.9.9"]),
             "cf.x.com": Host("cf.x.com", ips=["104.16.0.1"])}
    cf_nets = [ipaddress.ip_network("104.16.0.0/13")]
    monkeypatch.setattr(intel, "enrich_ipinfo", _no_ipinfo)
    # No apex SPF/MX candidates: keeps the test off the network, so the only
    # candidate is the unproxied in-scope host.
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _AbsentRecordResolver())
    out = await intel.cloudflare_origin_analysis(
        None, probe, ["x.com"], hosts, {}, cf_nets, active=True, resolver_ns=None)
    cand = out["candidates"]["9.9.9.9"]
    assert cand["confirmed"] is True
    assert "TLS cert" in cand["evidence"] and "www.x.com" in cand["evidence"]
    assert cand["cert"]["cn"] == "www.x.com"
    assert probe.calls == []                 # no HTTP request needed


async def test_cloudflare_origin_falls_back_to_host_header_when_cert_unhelpful(monkeypatch):
    """An out-of-scope or absent cert must not confirm, and must not stop the
    existing header probe from doing its job."""
    monkeypatch.setattr(intel, "fetch_cert", _fake_fetch_cert(
        {"9.9.9.9": {"cn": "shared-host.example", "sans": [], "issuer": "CA"}}))
    probe = _RecordingProbeClient(status=200, server="nginx")
    hosts = {"a.x.com": Host("a.x.com", ips=["9.9.9.9"]),
             "cf.x.com": Host("cf.x.com", ips=["104.16.0.1"])}
    monkeypatch.setattr(intel, "enrich_ipinfo", _no_ipinfo)
    # No apex SPF/MX candidates: keeps the test off the network, so the only
    # candidate is the unproxied in-scope host.
    monkeypatch.setattr(intel, "get_resolver", lambda ns: _AbsentRecordResolver())
    out = await intel.cloudflare_origin_analysis(
        None, probe, ["x.com"], hosts, {}, [ipaddress.ip_network("104.16.0.0/13")],
        active=True, resolver_ns=None)
    cand = out["candidates"]["9.9.9.9"]
    assert cand["confirmed"] is True
    assert cand["evidence"].startswith("Host: x.com")
    assert probe.calls                        # the header probe still ran


def _fake_fetch_cert(by_ip):
    async def fake(host, port=443, sni=None, timeout=6.0):
        return by_ip.get(host)
    return fake


async def _no_ipinfo(client, ip, token):
    return {}


class _RecordingProbeClient:
    """Records every request so 'no HTTP touch' can be asserted."""
    def __init__(self, status=None, server=""):
        self.calls = []
        self._status, self._server = status, server

    class _Resp:
        def __init__(self, status_code, headers):
            self.status_code, self.headers = status_code, headers

    async def get(self, url, **kwargs):
        self.calls.append(url)
        if self._status is None:
            raise Exception("connection refused")
        return self._Resp(self._status, {"server": self._server})


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


def _fake_dork_domain(monkeypatch, behavior, calls):
    """Patch core.dork_domain with a per-(provider, domain) script.

    `behavior(provider, domain)` returns (hits, terminal); `calls` records
    (provider, domain) in order so failover and resume points are observable.
    """
    async def fake(client, domain, provider, keys, limiter):
        calls.append((provider, domain))
        return behavior(provider, domain)
    monkeypatch.setattr(core, "dork_domain", fake)


def _hit(domain, n=1):
    return [{"link": f"https://{domain}/{n}", "category": "admin-panel",
             "severity": "medium"}]


async def test_run_dorks_falls_back_to_next_backend_on_terminal_failure(monkeypatch):
    """A dead first backend must not sink the sweep. Google CSE is closed to new
    customers, so a stale CSE key beside a working Brave key is realistic — it
    used to yield zero hits."""
    calls = []
    _fake_dork_domain(monkeypatch, lambda p, d: (
        ([], True) if p == "google" else (_hit(d), False)), calls)
    hits, used = await core._run_dorks(None, ["a.com", "b.com"],
                                       ["google", "brave"], {}, None)
    assert used == ["brave"]
    assert sorted(h["link"] for h in hits) == ["https://a.com/1", "https://b.com/1"]
    assert ("brave", "a.com") in calls and ("brave", "b.com") in calls


async def test_run_dorks_resumes_at_the_failing_domain_not_from_the_start(monkeypatch):
    """Earlier domains were fully swept, but the failing one aborted partway
    through its categories — so the fallback re-sweeps that one and continues,
    without re-burning quota on the domains already done."""
    calls = []
    _fake_dork_domain(monkeypatch, lambda p, d: (
        ([], True) if (p == "google" and d == "b.com")
        else (_hit(d), False)), calls)
    hits, used = await core._run_dorks(None, ["a.com", "b.com", "c.com"],
                                       ["google", "brave"], {}, None)
    assert [d for p, d in calls if p == "google"] == ["a.com", "b.com"]
    assert [d for p, d in calls if p == "brave"] == ["b.com", "c.com"]
    assert used == ["google", "brave"]
    assert len(hits) == 3                       # a from google, b+c from brave


async def test_run_dorks_dedupes_hits_across_backends(monkeypatch):
    """_run_templates only dedupes within one domain; two engines routinely
    index the same URL, so the cross-backend dedupe has to live here."""
    calls = []
    shared = [{"link": "https://a.com/same", "category": "git-exposure",
               "severity": "high"}]

    def behavior(provider, domain):
        if provider == "google":
            return (shared, False) if domain == "a.com" else ([], True)
        return shared + _hit("b.com"), False

    _fake_dork_domain(monkeypatch, behavior, calls)
    hits, _ = await core._run_dorks(None, ["a.com", "b.com"],
                                    ["google", "brave"], {}, None)
    assert [h["link"] for h in hits] == ["https://a.com/same", "https://b.com/1"]


async def test_run_dorks_non_terminal_result_does_not_switch_backends(monkeypatch):
    """Only a terminal failure justifies failover — an empty-but-healthy sweep
    must not burn a second backend's quota."""
    calls = []
    _fake_dork_domain(monkeypatch, lambda p, d: ([], False), calls)
    hits, used = await core._run_dorks(None, ["a.com"], ["google", "brave"], {}, None)
    assert hits == [] and used == []
    assert [p for p, _ in calls] == ["google"]          # brave never touched


async def test_run_dorks_gives_up_after_every_backend_fails_terminally(monkeypatch):
    calls = []
    _fake_dork_domain(monkeypatch, lambda p, d: ([], True), calls)
    hits, used = await core._run_dorks(None, ["a.com"],
                                       ["google", "brave", "vertex"], {}, None)
    assert hits == [] and used == []
    assert [p for p, _ in calls] == ["google", "brave", "vertex"]


async def test_run_dorks_single_backend_behaves_like_the_old_loop(monkeypatch):
    """Regression: with one configured backend, a terminal failure still stops
    the remaining domains rather than retrying them."""
    calls = []
    _fake_dork_domain(monkeypatch, lambda p, d: ([], True), calls)
    hits, used = await core._run_dorks(None, ["a.com", "b.com"], ["brave"], {}, None)
    assert hits == [] and used == []
    assert calls == [("brave", "a.com")]               # b.com never queried


def test_configured_dork_providers_lists_every_ready_backend_in_order():
    vertex = {"access_token": "t", "project": "p", "engine": "e"}
    keys = {"google_cse": "k", "google_cse_cx": "cx", "brave": "b", "vertex": vertex}
    assert dorking.configured_dork_providers(keys) == ["google", "brave", "vertex"]
    assert dorking.configured_dork_providers({"brave": "b", "vertex": vertex}) \
        == ["brave", "vertex"]
    assert dorking.configured_dork_providers({}) == []


def test_configured_dork_providers_explicit_choice_never_falls_back():
    """Pinning a backend must not silently use a different one."""
    keys = {"google_cse": "k", "google_cse_cx": "cx", "brave": "b"}
    assert dorking.configured_dork_providers(keys, "brave") == ["brave"]
    assert dorking.configured_dork_providers(keys, "vertex") == []   # not configured


# --------------------------------------------------------------------------- #
# Dork backend selection + Brave / Vertex providers
# --------------------------------------------------------------------------- #
def test_select_dork_provider_auto_prefers_google_then_brave_then_vertex():
    vertex = {"access_token": "t", "project": "p", "engine": "e"}
    both = {"google_cse": "k", "google_cse_cx": "cx", "brave": "b", "vertex": vertex}
    assert dorking.select_dork_provider(both) == "google"
    assert dorking.select_dork_provider({"brave": "b", "vertex": vertex}) == "brave"
    assert dorking.select_dork_provider({"vertex": vertex}) == "vertex"
    assert dorking.select_dork_provider({}) is None


def test_select_dork_provider_explicit_only_when_configured():
    keys = {"google_cse": "k", "google_cse_cx": "cx"}
    assert dorking.select_dork_provider(keys, "google") == "google"
    assert dorking.select_dork_provider(keys, "brave") is None      # not configured
    assert dorking.select_dork_provider(keys, "vertex") is None


def test_vertex_ready_needs_token_project_and_engine_or_datastore():
    assert dorking._vertex_ready({"access_token": "t", "project": "p", "engine": "e"}) is True
    assert dorking._vertex_ready({"access_token": "t", "project": "p", "datastore": "d"}) is True
    assert dorking._vertex_ready({"access_token": "t", "project": "p"}) is False   # no target
    assert dorking._vertex_ready({"project": "p", "engine": "e"}) is False         # no token
    assert dorking._vertex_ready(None) is False


def test_in_scope_matches_domain_and_subdomains_only():
    assert dorking._in_scope("https://x.com/a", "x.com") is True
    assert dorking._in_scope("https://sub.x.com/a", "x.com") is True
    assert dorking._in_scope("https://evilx.com/a", "x.com") is False   # not a suffix boundary
    assert dorking._in_scope("https://evil.com/a", "x.com") is False


def test_parse_brave_response_extracts_and_skips_linkless():
    data = {"web": {"results": [{"title": "Admin", "url": "https://x.com/admin", "description": "d"},
                                {"title": "no url"}]}}
    assert dorking._parse_brave_response(data) == [
        {"title": "Admin", "link": "https://x.com/admin", "snippet": "d"}]
    assert dorking._parse_brave_response({}) == []


def test_parse_vertex_response_pulls_link_title_snippet():
    data = {"results": [
        {"document": {"derivedStructData": {"link": "https://x.com/a", "title": "T",
                                            "snippets": [{"snippet": "s"}]}}},
        {"document": {"derivedStructData": {"title": "no link"}}}]}
    assert dorking._parse_vertex_response(data) == [
        {"title": "T", "link": "https://x.com/a", "snippet": "s"}]


async def test_brave_dork_tags_dedupes_scopes_and_sets_headers():
    calls = []

    async def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"url": url, "params": params, "headers": headers})
        return _FakeResp(200, {"web": {"results": [
            {"title": "Admin", "url": "https://x.com/admin", "description": "s"},
            {"title": "Off-scope", "url": "https://other.com/x", "description": "s"}]}})
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.brave_dork(client, "x.com", "bkey", limiter)
    assert len(calls) == len(dorking.DORK_TEMPLATES)             # one query per template
    assert len(out) == 1                                          # deduped + off-scope dropped
    assert out[0]["link"] == "https://x.com/admin"
    assert out[0]["category"] == dorking.DORK_TEMPLATES[0][0]
    assert terminal is False
    assert all(c["headers"]["X-Subscription-Token"] == "bkey" for c in calls)
    assert all(c["params"]["q"].startswith("site:x.com ") for c in calls)


async def test_brave_dork_stops_on_401_and_429():
    for code in (401, 429):
        async def fake_get(url, params=None, headers=None, timeout=None):
            return _FakeResp(code)
        client = type("C", (), {"get": staticmethod(fake_get)})()
        limiter = enrich.RateLimiter(per_second=1000)
        out, terminal = await dorking.brave_dork(client, "x.com", "bad", limiter)
        assert out == []
        assert terminal is True


async def test_brave_dork_network_exception_not_terminal():
    async def fake_get(url, params=None, headers=None, timeout=None):
        raise Exception("boom")
    client = type("C", (), {"get": staticmethod(fake_get)})()
    limiter = enrich.RateLimiter(per_second=1000)
    out, terminal = await dorking.brave_dork(client, "x.com", "b", limiter)
    assert out == []
    assert terminal is False


async def test_vertex_dork_posts_to_serving_config_with_bearer_and_scopes():
    calls = []

    async def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "json": json, "headers": headers})
        return _FakeResp(200, {"results": [
            {"document": {"derivedStructData": {"link": "https://x.com/admin", "title": "T",
                                                "snippets": [{"snippet": "s"}]}}}]})
    client = type("C", (), {"post": staticmethod(fake_post)})()
    limiter = enrich.RateLimiter(per_second=1000)
    creds = {"access_token": "tok", "project": "proj", "location": "global", "engine": "eng"}
    out, terminal = await dorking.vertex_dork(client, "x.com", creds, limiter)
    assert len(out) == 1 and out[0]["link"] == "https://x.com/admin"
    assert terminal is False
    assert all(c["headers"]["Authorization"] == "Bearer tok" for c in calls)
    assert all("engines/eng/servingConfigs/default_search:search" in c["url"] for c in calls)
    assert all(c["json"]["query"].startswith("site:x.com ") for c in calls)


async def test_vertex_dork_terminal_when_config_incomplete():
    client = type("C", (), {"post": staticmethod(lambda *a, **k: None)})()
    limiter = enrich.RateLimiter(per_second=1000)
    # missing engine/datastore -> no serving-config URL -> terminal, no requests
    out, terminal = await dorking.vertex_dork(client, "x.com",
                                              {"access_token": "t", "project": "p"}, limiter)
    assert out == []
    assert terminal is True


async def test_vertex_dork_stops_on_403():
    async def fake_post(url, json=None, headers=None, timeout=None):
        return _FakeResp(403)
    client = type("C", (), {"post": staticmethod(fake_post)})()
    limiter = enrich.RateLimiter(per_second=1000)
    creds = {"access_token": "t", "project": "p", "datastore": "ds"}
    out, terminal = await dorking.vertex_dork(client, "x.com", creds, limiter)
    assert out == []
    assert terminal is True


async def test_dork_domain_dispatches_by_provider(monkeypatch):
    seen = {}

    async def fake_brave(client, domain, key, limiter):
        seen["brave"] = (domain, key)
        return [{"link": "https://x.com/a", "category": "c", "severity": "high"}], False
    monkeypatch.setattr(dorking, "brave_dork", fake_brave)
    keys = {"brave": "bk"}
    out, terminal = await dorking.dork_domain(None, "x.com", "brave", keys, None)
    assert seen["brave"] == ("x.com", "bk")
    assert out and terminal is False


def test_resolve_vertex_merges_config_env_cli_with_precedence(monkeypatch):
    from lrecon import common
    monkeypatch.delenv("VERTEX_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("VERTEX_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setenv("VERTEX_PROJECT", "env-proj")          # env overrides config
    args = argparse.Namespace(vertex_access_token="cli-tok",   # CLI overrides env/config
                              vertex_project=None, vertex_location=None,
                              vertex_engine=None, vertex_datastore=None)
    cfg = {"access_token": "cfg-tok", "project": "cfg-proj", "engine": "cfg-eng"}
    out = common._resolve_vertex(cfg, args)
    assert out["access_token"] == "cli-tok"
    assert out["project"] == "env-proj"
    assert out["engine"] == "cfg-eng"
    assert out["location"] == "global"                        # defaulted


def test_resolve_vertex_returns_none_when_nothing_configured(monkeypatch):
    from lrecon import common
    for v in ("VERTEX_ACCESS_TOKEN", "GOOGLE_ACCESS_TOKEN", "VERTEX_PROJECT",
              "GOOGLE_CLOUD_PROJECT", "VERTEX_LOCATION", "VERTEX_ENGINE", "VERTEX_DATASTORE"):
        monkeypatch.delenv(v, raising=False)
    args = argparse.Namespace(vertex_access_token=None, vertex_project=None,
                              vertex_location=None, vertex_engine=None, vertex_datastore=None)
    assert common._resolve_vertex(None, args) is None


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
                      "unclaimed-service signature matched",
             takeover_confidence="likely"),
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
    async def fake_run_nuclei(cmd, stdin=None, timeout=1800):
        return ('{"host":"x.com","template-id":"t","matched-at":"https://x.com",'
                '"info":{"name":"Bug","severity":"high",'
                '"classification":{"cve-id":["CVE-2026-1"]}}}')
    monkeypatch.setattr(backends, "_run_nuclei", fake_run_nuclei)
    res = await backends.nuclei_scan(["https://x.com"])
    assert res[0]["severity"] == "high"
    assert res[0]["cve"] == ["CVE-2026-1"]


def test_looks_like_nuclei_finding_requires_both_fields():
    assert backends._looks_like_nuclei_finding(
        '{"template-id":"t","matched-at":"https://x.com"}') is True
    # a -stats status line: valid JSON, but not a finding
    assert backends._looks_like_nuclei_finding(
        '{"duration":"5s","hosts":3,"requests":120,"rps":24}') is False
    assert backends._looks_like_nuclei_finding("not json at all") is False
    assert backends._looks_like_nuclei_finding('{"template-id":"t"}') is False   # missing matched-at


class _FakeStreamReader:
    """Async-iterable fake for asyncio.StreamReader — yields pre-canned
    byte lines then raises StopAsyncIteration, matching `async for line in
    reader` usage."""
    def __init__(self, lines):
        self._lines = [l if isinstance(l, bytes) else l.encode() for l in lines]

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


class _FakeStreamWriter:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data):
        self.written += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class _FakeNucleiProc:
    def __init__(self, stdout_lines, stderr_lines):
        self.stdin = _FakeStreamWriter()
        self.stdout = _FakeStreamReader(stdout_lines)
        self.stderr = _FakeStreamReader(stderr_lines)
        self.returncode = 0
        self.killed = False

    async def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


async def test_run_nuclei_separates_findings_from_progress_and_streams_stderr(monkeypatch):
    stdout_lines = [
        '{"duration":"5s","hosts":3,"matched":0,"requests":120,"rps":24}\n',   # stats line
        '{"host":"x.com","template-id":"t1","matched-at":"https://x.com",'
        '"info":{"severity":"high"}}\n',
        "\n",                                                                  # blank -> skipped
    ]
    stderr_lines = ["[INF] some nuclei banner line\n"]
    fake_proc = _FakeNucleiProc(stdout_lines, stderr_lines)

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return fake_proc
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    logged = []
    monkeypatch.setattr(backends, "log", lambda msg: logged.append(msg))

    out = await backends._run_nuclei(["nuclei"], stdin=b"https://x.com\n", timeout=30)
    assert '"template-id":"t1"' in out
    assert "duration" not in out                       # stats line not returned as a finding
    assert fake_proc.stdin.written == b"https://x.com\n"
    assert fake_proc.stdin.closed is True
    assert any("duration" in m for m in logged)         # stats line logged live
    assert any("banner" in m for m in logged)           # stderr line logged live


async def test_run_nuclei_kills_process_on_timeout(monkeypatch):
    class _HangingStreamReader:
        def __aiter__(self):
            return self

        async def __anext__(self):
            await asyncio.sleep(10)   # never resolves within the test's timeout budget
            raise StopAsyncIteration

    class _HangingProc:
        def __init__(self):
            self.stdin = _FakeStreamWriter()
            self.stdout = _HangingStreamReader()
            self.stderr = _HangingStreamReader()
            self.returncode = None
            self.killed = False

        async def wait(self):
            return 0

        def kill(self):
            self.killed = True
            self.returncode = -9

    fake_proc = _HangingProc()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return fake_proc
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    logged = []
    monkeypatch.setattr(backends, "log", lambda msg: logged.append(msg))

    out = await backends._run_nuclei(["nuclei"], stdin=b"x\n", timeout=0.05)
    assert out == ""
    assert fake_proc.killed is True
    assert any("timed out" in m for m in logged)


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
def test_write_csv_one_row_per_subdomain_ip_pair():
    hosts = [
        Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC",
             country="US", scheme="https", http_status=200, source={"crtsh"},
             ip_asn={"1.2.3.4": "AS15169"}, ip_org={"1.2.3.4": "Google LLC"}),
        # multi-IP host: subdomain repeats, one row per IP, only one IP
        # resolved to an org — the other row's org stays blank rather
        # than falling back to a scalar that may belong to a different
        # IP on the same host.
        Host("multi.x.com", ips=["9.9.9.9", "8.8.8.8"], wildcard=True, source={"seed"},
             ip_asn={"8.8.8.8": "AS15169"}, ip_org={"8.8.8.8": "Google LLC"}),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        n = report.write_csv(hosts, str(path))
        rows = list(csv.DictReader(path.open()))
    assert n == 3                                  # 1 + 2 IP rows
    assert list(rows[0].keys()) == ["subdomain", "ip", "org"]
    assert rows[0] == {"subdomain": "a.x.com", "ip": "1.2.3.4", "org": "Google LLC"}
    assert rows[1] == {"subdomain": "multi.x.com", "ip": "9.9.9.9", "org": ""}
    assert rows[2] == {"subdomain": "multi.x.com", "ip": "8.8.8.8", "org": "Google LLC"}


def test_write_csv_single_ip_host_falls_back_to_scalar_org():
    # ip_org wasn't populated (e.g. a caller of apply_ipinfo() that omitted
    # the optional ip arg), but h.org is known and unambiguous for one IP.
    h = Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        report.write_csv([h], str(path))
        rows = list(csv.DictReader(path.open()))
    assert rows[0]["org"] == "Google LLC"


def test_write_csv_host_with_no_resolved_ips_still_gets_a_row():
    h = Host("unresolved.x.com", ips=[])
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        n = report.write_csv([h], str(path))
        rows = list(csv.DictReader(path.open()))
    assert n == 1
    assert rows[0] == {"subdomain": "unresolved.x.com", "ip": "", "org": ""}


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


def _email_res(spf_parsed, spf="v=spf1 include:b.test -all"):
    return {"email": {"x.com": {"domain": "x.com", "grade": "WARN", "spf": spf,
                                "dmarc": None, "dkim": False, "dkim_selector": None,
                                "dkim_record": None, "spf_parsed": spf_parsed,
                                "dmarc_parsed": {}, "issues": []}}}


def test_spf_lookups_labels_the_count_it_actually_measured():
    """The budget spans include:/redirect= expansion, so a bare `n/10` would
    overclaim. Each state gets its own label, and an over-limit count — which
    stops early and is therefore a lower bound — is marked "at least"."""
    base = {"includes": ["b.test"], "redirect": None}
    # Clean, fully expanded count.
    assert report._spf_lookups(
        {**base, "lookup_count": 4, "lookup_count_complete": True,
         "exceeds_lookup_limit": False}) == ("4/10", "includes expanded", "")
    # Nothing delegates: no caveat needed at all.
    assert report._spf_lookups(
        {"includes": [], "redirect": None, "lookup_count": 2,
         "lookup_count_complete": True, "exceeds_lookup_limit": False}) == ("2/10", "", "")
    # Confirmed permerror, count cut short at the cap -> "≥", flagged bad.
    count, caveat, level = report._spf_lookups(
        {**base, "lookup_count": 12, "lookup_count_complete": False,
         "exceeds_lookup_limit": True})
    assert count == "≥12/10" and level == "bad" and "permerror" in caveat
    # A nested lookup failed: not an accusation, but not a compliance claim.
    count, caveat, level = report._spf_lookups(
        {**base, "lookup_count": 4, "lookup_count_complete": False,
         "exceeds_lookup_limit": False})
    assert count == "4/10" and level == "warn" and "incomplete" in caveat


def test_write_markdown_spf_lookup_count_carries_its_caveat():
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = _email_res({"includes": ["b.test"], "redirect": None, "all_qualifier": "-",
                      "lookup_count": 4, "lookup_count_complete": False,
                      "exceeds_lookup_limit": False})
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert "SPF DNS lookups:** 4/10" in content
    assert "incomplete" in content          # never a bare n/10 when unverified


def test_write_html_spf_lookup_count_flags_a_confirmed_permerror():
    hosts = [Host("a.x.com", ips=["1.2.3.4"])]
    res = _email_res({"includes": ["b.test"], "redirect": None, "all_qualifier": "-",
                      "lookup_count": 12, "lookup_count_complete": False,
                      "exceeds_lookup_limit": True})
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert 'class="bad"' in content
    assert "&ge;12/10" in content or "≥12/10" in content
    assert "permerror" in content


def _takeover_hosts():
    return [
        Host("weak.x.com", ips=["1.2.3.4"], cname="w.s3.amazonaws.com",
             takeover="CNAME -> w.s3.amazonaws.com (s3.amazonaws.com); verify",
             takeover_confidence="possible"),
        Host("gone.x.com", cname="g.example.net",
             takeover="Dangling CNAME -> g.example.net; target name does not exist (NXDOMAIN)",
             takeover_confidence="confirmed"),
    ]


def test_write_markdown_takeover_shows_confidence_confirmed_first():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown(_takeover_hosts(), ["x.com"], {}, str(path))
        content = path.read_text()
    assert "confirmed — CNAME target does not exist" in content
    assert "possible — takeover-prone provider" in content
    # Highest confidence first: that's the order the leads get worked in.
    assert content.index("gone.x.com") < content.index("weak.x.com")


def test_write_html_takeover_has_confidence_column():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(_takeover_hosts(), ["x.com"], {}, str(path))
        content = path.read_text()
    assert "<th>Confidence</th>" in content
    assert 'class="bad"' in content and 'class="warn"' in content
    assert content.index("gone.x.com") < content.index("weak.x.com")


def test_takeover_report_tolerates_a_lead_with_no_confidence_set():
    """An unlabelled lead must still render, not vanish or raise."""
    hosts = [Host("old.x.com", cname="c", takeover="found some other way")]
    with tempfile.TemporaryDirectory() as d:
        md, html = Path(d) / "r.md", Path(d) / "r.html"
        report.write_markdown(hosts, ["x.com"], {}, str(md))
        report.write_html(hosts, ["x.com"], {}, str(html))
        assert "old.x.com" in md.read_text()
        assert "old.x.com" in html.read_text()


def _cert_res():
    return {"certs": [
        {"host": "www.x.com", "port": 443, "cn": "www.x.com",
         "sans": ["www.x.com", "api.x.com"], "issuer": "Real CA",
         "not_after": "2027-01-01T00:00:00+00:00", "not_before": "2026-01-01T00:00:00+00:00",
         "expired": False, "not_yet_valid": False, "days_to_expiry": 400,
         "self_signed": False},
        {"host": "mail.x.com", "port": 993, "cn": "mail.x.com", "sans": [],
         "issuer": "mail.x.com", "not_after": "2020-01-01T00:00:00+00:00",
         "not_before": "2019-01-01T00:00:00+00:00", "expired": True,
         "not_yet_valid": False, "days_to_expiry": -2000, "self_signed": True},
    ]}


def test_cert_flags_names_every_condition_worth_attention():
    good = {"expired": False, "not_yet_valid": False, "self_signed": False,
            "days_to_expiry": 400}
    assert report._cert_flags(good) == []
    soon = {**good, "days_to_expiry": 5}
    assert report._cert_flags(soon) == ["expires in 5d"]
    bad = {"expired": True, "not_yet_valid": False, "self_signed": True,
           "days_to_expiry": -10}
    flags = report._cert_flags(bad)
    assert "expired" in flags and "self-signed" in flags
    # An already-expired cert shouldn't also claim it "expires in -10d".
    assert not any("expires in" in f for f in flags)


def test_write_markdown_cert_section_lists_endpoints_flagged_first():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown([Host("www.x.com", ips=["1.2.3.4"])], ["x.com"],
                              _cert_res(), str(path))
        content = path.read_text()
    assert "TLS certificates (as served)" in content
    assert "`mail.x.com:993`" in content and "`www.x.com:443`" in content
    assert "expired" in content and "self-signed" in content
    # The flagged cert is the row that matters, so it sorts first.
    assert content.index("mail.x.com:993") < content.index("www.x.com:443")


def test_write_html_cert_section_flags_bad_certs():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html([Host("www.x.com", ips=["1.2.3.4"])], ["x.com"],
                          _cert_res(), str(path))
        content = path.read_text()
    assert "TLS certificates (as served)" in content
    assert "<th>SANs</th>" in content
    assert 'class="bad"' in content
    assert content.index("mail.x.com") < content.index("www.x.com:443")


def test_cert_section_absent_when_no_certs_read():
    """A run without the [tls] extra must not emit an empty section."""
    with tempfile.TemporaryDirectory() as d:
        md, html = Path(d) / "r.md", Path(d) / "r.html"
        report.write_markdown([Host("a.x.com")], ["x.com"], {}, str(md))
        report.write_html([Host("a.x.com")], ["x.com"], {}, str(html))
        assert "TLS certificates" not in md.read_text()
        assert "TLS certificates" not in html.read_text()


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


def test_write_html_whois_shows_source_and_vt_mirror_cross_reference():
    hosts = [Host("a.io", ips=["1.2.3.4"])]
    res = {
        "whois": {"x.io": {**intel.empty_whois_entry(), "registrar": "WHOIS43 Registrar",
                           "source": "whois43"}},
        "vt": {"x.io": {"whois": "Domain Name: X.IO\nRegistrar: WHOIS43 Registrar\n"}},
    }
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.io"], res, str(path))
        content = path.read_text()
    assert "WHOIS (port 43)" in content


def test_whois_source_label_handles_all_combinations():
    assert report._whois_source_label(None) == "—"
    assert report._whois_source_label("rdap") == "RDAP"
    assert report._whois_source_label("whois43") == "WHOIS (port 43)"
    assert report._whois_source_label("vt-whois") == "VT WHOIS mirror"
    assert report._whois_source_label("rdap+whois43") == "RDAP + WHOIS (port 43)"
    assert report._whois_source_label("rdap+vt-whois") == "RDAP + VT WHOIS mirror"
    assert report._whois_source_label("rdap+whois43+vt-whois") == \
        "RDAP + WHOIS (port 43) + VT WHOIS mirror"


def test_write_html_whois_omits_vt_mirror_when_registrar_already_found():
    # VT's raw text is only surfaced as a cross-reference when the
    # structured lookup came up empty — not shown otherwise, to avoid
    # dumping an unparsed wall of text when it isn't needed.
    hosts = [Host("a.com", ips=["1.2.3.4"])]
    res = {
        "whois": {"x.com": {**intel.empty_whois_entry(), "registrar": "MarkMonitor Inc.",
                            "source": "rdap"}},
        "vt": {"x.com": {"whois": "Domain Name: X.COM\nRegistrar: MarkMonitor Inc.\n"}},
    }
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.html"
        report.write_html(hosts, ["x.com"], res, str(path))
        content = path.read_text()
    assert "VirusTotal WHOIS mirror" not in content
    assert "RDAP</td>" in content


def test_write_markdown_whois_shows_source_and_vt_mirror_cross_reference():
    hosts = [Host("a.io", ips=["1.2.3.4"])]
    res = {
        "whois": {"x.io": {**intel.empty_whois_entry(), "source": None}},
        "vt": {"x.io": {"whois": "Domain Name: X.IO\nRegistrar: Some Registrar\n"}},
    }
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "r.md"
        report.write_markdown(hosts, ["x.io"], res, str(path))
        content = path.read_text()
    assert "VirusTotal WHOIS mirror" in content
    assert "Some Registrar" in content


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
    assert args.asn_expand is True
    # active/target-touching checks must never be flipped on by --all —
    # nuclei sends live HTTP requests (including exploit/auth-bypass
    # probes) straight at the target's hosts, same tier as active_ports
    # and verify_emails, and is gated behind `not passive_only` in core.py
    # for exactly that reason.
    assert args.nuclei is False
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


def test_cli_no_subcommand_runs_default_recon(monkeypatch):
    # Back-compat: `lrecon example.com` must still route into the flat recon
    # flow, unchanged by the subcommand dispatch.
    called = {}

    def fake_recon(argv=None, emit_dossier=False):
        called["argv"] = argv
        called["emit_dossier"] = emit_dossier
    monkeypatch.setattr(cli, "_recon", fake_recon)
    monkeypatch.setattr(sys, "argv", ["lrecon", "example.com"])
    cli.main()
    assert called["argv"] == ["example.com"]
    assert called["emit_dossier"] is False


def test_cli_dossier_subcommand_sets_emit_flag(monkeypatch):
    called = {}

    def fake_recon(argv=None, emit_dossier=False):
        called["argv"] = argv
        called["emit_dossier"] = emit_dossier
    monkeypatch.setattr(cli, "_recon", fake_recon)
    monkeypatch.setattr(sys, "argv", ["lrecon", "dossier", "--company", "Acme", "acme.com"])
    cli.main()
    assert called["argv"] == ["--company", "Acme", "acme.com"]
    assert called["emit_dossier"] is True


def test_cli_full_report_subcommand_sets_emit_flag(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "_recon", lambda argv=None, emit_dossier=False: called.update(
        argv=argv, emit=emit_dossier))
    monkeypatch.setattr(sys, "argv", ["lrecon", "full-report", "acme.com"])
    cli.main()
    assert called["emit"] is True


def test_cli_enum_subcommand_dispatches(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "_cmd_enum", lambda argv: called.update(argv=argv))
    monkeypatch.setattr(sys, "argv", ["lrecon", "enum", "--company", "Acme", "acme.com"])
    cli.main()
    assert called["argv"] == ["--company", "Acme", "acme.com"]


def test_cli_check_llm_early_returns(monkeypatch, capsys):
    # --check-llm probes the backend and exits before recon. Stub the probe.
    async def fake_check(cfg):
        return {"provider": cfg.provider, "model": cfg.model, "base_url": cfg.base_url,
                "reachable": False, "note": "stubbed"}
    monkeypatch.setattr(cli, "_check_llm", fake_check)
    monkeypatch.setattr(sys, "argv", ["lrecon", "--check-llm", "--config", "/nonexistent"])
    cli.main()                                          # must not require a domain
    assert "LLM backend self-check" in capsys.readouterr().err   # log() -> stderr


def test_cli_company_alias_and_domain_merge(monkeypatch):
    # `--company` aliases `--company-name`; `--domain` merges into positional.
    captured = {}

    def fake_run(domains, args, keys):
        captured["domains"] = domains
        captured["company"] = args.company_name
        raise SystemExit(0)                             # bail before output writing
    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setattr(sys, "argv",
                        ["lrecon", "--company", "Acme Corp", "--domain", "b.com",
                         "--passive-only", "--config", "/nonexistent", "a.com"])
    with pytest.raises(SystemExit):
        cli.main()
    assert set(captured["domains"]) == {"a.com", "b.com"}
    assert captured["company"] == "Acme Corp"


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


# --------------------------------------------------------------------------- #
# LLM abstraction layer (lrecon/llm.py)
# --------------------------------------------------------------------------- #
class _FakeLLMResp:
    def __init__(self, data, status=200):
        self._d = data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._d


class _FakeLLMClient:
    """Records the last POST and replays a canned JSON body. `fail_times`
    raises before succeeding, to exercise retry/backoff."""
    def __init__(self, data, fail_times=0):
        self.data = data
        self.fail_times = fail_times
        self.calls = 0
        self.last = None

    async def post(self, url, headers=None, json=None, timeout=None):
        self.calls += 1
        self.last = {"url": url, "headers": headers or {}, "json": json}
        if self.calls <= self.fail_times:
            raise ConnectionError("boom")
        return _FakeLLMResp(self.data)


def _no_sleep(monkeypatch):
    async def _s(*a, **k):
        return None
    monkeypatch.setattr(llm.asyncio, "sleep", _s)


async def test_llm_openai_compat_shapes_request_and_reads_choice():
    c = _FakeLLMClient({"choices": [{"message": {"content": " hi there "}}]})
    cfg = llm.LLMConfig(provider="ollama", model="llama3.1")
    out = await llm.complete(c, cfg, [{"role": "user", "content": "q"}])
    assert out == "hi there"
    assert c.last["url"].endswith("/chat/completions")
    assert c.last["json"]["model"] == "llama3.1"
    assert "Authorization" not in c.last["headers"]     # local, no key


async def test_llm_openai_compat_sends_bearer_when_keyed():
    c = _FakeLLMClient({"choices": [{"message": {"content": "x"}}]})
    cfg = llm.LLMConfig(provider="openai", model="gpt-4o", api_key="sk-abc")
    await llm.complete(c, cfg, [{"role": "user", "content": "q"}])
    assert c.last["headers"]["Authorization"] == "Bearer sk-abc"


async def test_llm_anthropic_uses_system_field_and_headers():
    c = _FakeLLMClient({"content": [{"type": "text", "text": "ans"}], "stop_reason": "end_turn"})
    cfg = llm.LLMConfig(provider="anthropic", model="claude-opus-5", api_key="k")
    out = await llm.complete(c, cfg, [{"role": "system", "content": "sys"},
                                      {"role": "user", "content": "hi"}])
    assert out == "ans"
    assert c.last["url"].endswith("/messages")
    assert c.last["headers"]["x-api-key"] == "k"
    assert c.last["headers"]["anthropic-version"] == "2023-06-01"
    assert c.last["json"]["system"] == "sys"            # system split out of messages
    assert all(m["role"] != "system" for m in c.last["json"]["messages"])


async def test_llm_google_folds_system_into_first_user_turn():
    c = _FakeLLMClient({"candidates": [{"content": {"parts": [{"text": "g"}]}}]})
    cfg = llm.LLMConfig(provider="google", model="gemini-1.5-flash", api_key="gk")
    out = await llm.complete(c, cfg, [{"role": "system", "content": "SYS"},
                                      {"role": "user", "content": "hi"}])
    assert out == "g"
    assert "generateContent" in c.last["url"] and c.last["url"].endswith("key=gk")
    assert c.last["json"]["contents"][0]["parts"][0]["text"].startswith("SYS")


async def test_llm_unknown_provider_returns_none():
    cfg = llm.LLMConfig(provider="nope", model="m")
    assert await llm.complete(_FakeLLMClient({}), cfg, [{"role": "user", "content": "q"}]) is None


async def test_llm_retries_then_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    c = _FakeLLMClient({"choices": [{"message": {"content": "ok"}}]}, fail_times=2)
    cfg = llm.LLMConfig(provider="ollama", model="m")
    out = await llm.complete(c, cfg, [{"role": "user", "content": "q"}])
    assert out == "ok"
    assert c.calls == 3                                 # 2 failures + 1 success


async def test_llm_falls_back_to_secondary_provider(monkeypatch):
    _no_sleep(monkeypatch)

    # Primary always fails; fallback (a different provider) answers. Because
    # both go through the same fake client, distinguish by the response shape:
    # the fake returns an OpenAI-style body, which only the compat adapter reads.
    class _PrimaryFails:
        def __init__(self):
            self.calls = 0

        async def post(self, url, headers=None, json=None, timeout=None):
            self.calls += 1
            if "/messages" in url:                      # anthropic primary
                raise ConnectionError("down")
            return _FakeLLMResp({"choices": [{"message": {"content": "from-fallback"}}]})

    fb = llm.LLMConfig(provider="ollama", model="local")
    cfg = llm.LLMConfig(provider="anthropic", model="claude-opus-5", api_key="k", fallback=fb)
    out = await llm.complete(_PrimaryFails(), cfg, [{"role": "user", "content": "q"}])
    assert out == "from-fallback"


def test_llm_config_per_module_overrides():
    cfg = llm.LLMConfig(provider="ollama", model="base", temperature=0.2, max_tokens=1024,
                        per_module={"news": {"model": "fast", "max_tokens": 256}})
    assert cfg.for_module("news") == {"model": "fast", "temperature": 0.2, "max_tokens": 256}
    assert cfg.for_module("dossier") == {"model": "base", "temperature": 0.2, "max_tokens": 1024}
    assert cfg.for_module(None)["model"] == "base"


def test_llm_config_is_cloud_flag():
    assert llm.LLMConfig(provider="ollama").is_cloud is False
    assert llm.LLMConfig(provider="lmstudio").is_cloud is False
    assert llm.LLMConfig(provider="anthropic").is_cloud is True
    assert llm.LLMConfig(provider="openai").is_cloud is True


def test_llm_config_from_keys_selects_provider_key():
    keys = {"llm": {"provider": "anthropic", "model": "claude-opus-5"},
            "openai": "o", "anthropic": "a", "google_ai": "g"}
    cfg = llm.config_from_keys(keys)
    assert cfg.provider == "anthropic" and cfg.api_key == "a"
    # default when nothing configured -> local ollama, no key
    cfg2 = llm.config_from_keys({"llm": None})
    assert cfg2.provider == "ollama" and cfg2.api_key is None


def test_llm_config_defaults_local_base_urls():
    assert "11434" in llm.LLMConfig(provider="ollama").base_url
    assert "1234" in llm.LLMConfig(provider="lmstudio").base_url
    assert llm.LLMConfig(provider="anthropic").base_url.endswith("anthropic.com/v1")


async def test_check_llm_reports_reachability(monkeypatch):
    _no_sleep(monkeypatch)                              # skip retry backoff on the dead-client path
    c = _FakeLLMClient({"choices": [{"message": {"content": "ok"}}]})
    row = await llm.check_llm(c, llm.LLMConfig(provider="ollama", model="m"))
    assert row["reachable"] is True and row["provider"] == "ollama"

    class _Dead:
        async def post(self, *a, **k):
            raise ConnectionError("nope")
    row2 = await llm.check_llm(_Dead(), llm.LLMConfig(provider="ollama", model="m"))
    assert row2["reachable"] is False


# --------------------------------------------------------------------------- #
# Factual news / company-intel (lrecon/news.py) — no pretext scoring
# --------------------------------------------------------------------------- #
def test_news_parse_summary_variants():
    fenced = news._parse_summary('```json\n{"summary":"s","events":[{"bucket":"m&a","description":"d"}]}\n```')
    assert fenced["summary"] == "s"
    assert fenced["events"][0]["bucket"] == "m&a"
    # bogus bucket normalized to "other"
    prose = news._parse_summary('note: {"summary":"x","events":[{"bucket":"zzz","description":"d"}]} end')
    assert prose["events"][0]["bucket"] == "other"
    assert news._parse_summary("no json") == {}
    assert news._parse_summary("") == {}


def test_news_summary_output_has_no_pretext_fields():
    # Guard the scope boundary: whatever the model returns, the parsed shape
    # exposes only neutral factual fields — never a pretext/lure/score field.
    parsed = news._parse_summary(
        '{"summary":"s","events":[{"bucket":"exec-change","description":"CFO left",'
        '"pretext_potential":"HIGH","lure":"click here"}]}')
    ev = parsed["events"][0]
    assert set(ev.keys()) == {"bucket", "description", "date", "source"}
    assert "pretext_potential" not in ev and "lure" not in ev


async def test_news_edgar_parse_and_company_intel(monkeypatch):
    edgar = {"hits": {"hits": [
        {"_source": {"display_names": ["ACME CORP  (CIK 0000123)"], "file_type": "8-K",
                     "file_date": "2026-01-15", "ciks": ["0000123"], "adsh": "0001-23-000045"}},
    ]}}

    class _C:
        async def get(self, url, params=None, headers=None, timeout=None):
            return _FakeLLMResp(edgar)
    filings = await news.edgar_recent_filings(_C(), "Acme Corp")
    assert filings and filings[0]["form"] == "8-K" and filings[0]["date"] == "2026-01-15"

    # company_intel with a stubbed LLM summarizer
    async def fake_complete(client, cfg, messages, module=None, **kw):
        return '{"summary":"Acme makes widgets.","events":[{"bucket":"product","description":"launched X"}]}'
    monkeypatch.setattr(news.llm, "complete", fake_complete)

    class _C2:
        async def get(self, url, params=None, headers=None, timeout=None):
            return _FakeLLMResp(edgar)
    out = await news.company_intel(_C2(), "Acme Corp", "acme.com",
                                   llm.LLMConfig(provider="ollama", model="m"))
    assert out["summary"] == "Acme makes widgets."
    assert out["events"][0]["bucket"] == "product"


async def test_news_company_intel_empty_when_nothing_found(monkeypatch):
    class _C:
        async def get(self, url, params=None, headers=None, timeout=None):
            return _FakeLLMResp({"hits": {"hits": []}})
    out = await news.company_intel(_C(), "Nobody Ltd", "nobody.com",
                                   llm.LLMConfig(provider="ollama", model="m"))
    assert out["summary"] is None and out["events"] == []


# --------------------------------------------------------------------------- #
# Dossier generator (lrecon/dossier.py)
# --------------------------------------------------------------------------- #
def _synthetic_res():
    h = Host("www.acme.com", ips=["1.2.3.4"], tech=["nginx", "React"], server="nginx",
             http_status=200, scheme="https", tech_confirmed=True)
    return {
        "hosts": [h],
        "mail_infra": {"acme.com": [{"host": "mx.acme.com", "provider": "Google Workspace",
                                     "priority": 10}]},
        "dns": {"acme.com": {"ns": ["ns1.acme.com"]}},
        "whois": {"acme.com": {"registrant_org": "Acme Corp", "registrar": "MarkMonitor"}},
        "entry_points": [{"type": "auth-surface", "target": "sso.acme.com",
                          "severity": "info", "summary": "OIDC exposed — Okta"}],
        "auth_surface": [{"host": "sso.acme.com", "idp": "Okta",
                          "issuer": "https://acme.okta.com",
                          "oidc_config_url": "https://sso.acme.com/.well-known/openid-configuration"}],
        "people": [Person(email="jane@acme.com", name="Jane Doe", position="CTO",
                          source={"hunter"})],
    }


async def test_build_dossier_structured_only_without_llm():
    d = await dossier.build_dossier(None, _synthetic_res(), ["acme.com"], "Acme Corp",
                                    llm_cfg=None, news=None)
    assert d["generated_with_llm"] is False
    assert d["company_profile"]["narrative"] is None
    assert d["tech_stack"]["data"]["web_tech"] == ["React", "nginx"]
    assert d["tech_stack"]["data"]["mail_collab_providers"] == ["Google Workspace"]
    assert d["tech_stack"]["data"]["web_tech_confirmed_live"] == ["React", "nginx"]
    assert d["auth_surface"]["data"][0]["idp"] == "Okta"
    assert d["people"]["data"][0]["email"] == "jane@acme.com"


async def test_build_dossier_with_llm_adds_narrative(monkeypatch):
    async def fake_complete(client, cfg, messages, module=None, **kw):
        return f"narrative for {module}"
    monkeypatch.setattr(dossier.llm, "complete", fake_complete)
    news_intel = {"summary": "Acme makes widgets.",
                  "events": [{"bucket": "m&a", "description": "Acquired Foo", "date": "2026-01"}]}
    d = await dossier.build_dossier(object(), _synthetic_res(), ["acme.com"], "Acme Corp",
                                    llm_cfg=llm.LLMConfig(provider="ollama", model="m"),
                                    news=news_intel)
    assert d["generated_with_llm"] is True
    assert d["company_profile"]["narrative"] == "narrative for dossier"
    assert d["company_profile"]["data"]["news_summary"] == "Acme makes widgets."
    assert d["company_profile"]["data"]["recent_events"][0]["bucket"] == "m&a"


async def test_dossier_writers_json_and_markdown():
    import json as _json
    d = await dossier.build_dossier(None, _synthetic_res(), ["acme.com"], "Acme Corp", llm_cfg=None)
    with tempfile.TemporaryDirectory() as td:
        jp = Path(td) / "d.dossier.json"
        mp = Path(td) / "d.dossier.md"
        dossier.write_dossier_json(d, str(jp))
        dossier.write_dossier_md(d, str(mp))
        parsed = _json.loads(jp.read_text())          # valid machine-readable JSON
        assert parsed["company"] == "Acme Corp"
        md = mp.read_text()
    assert "# Target dossier — Acme Corp" in md
    assert "Google Workspace" in md
    assert "sso.acme.com" in md
    assert "jane@acme.com" in md
    assert "structured findings only" in md            # no-LLM note present


# --------------------------------------------------------------------------- #
# Passive auth-surface mapping (lrecon/intel.py)
# --------------------------------------------------------------------------- #
class _AuthResp:
    def __init__(self, status, data, url):
        self.status_code = status
        self._d = data
        self.url = url

    def json(self):
        if self._d is None:
            raise ValueError("no json")
        return self._d


class _AuthClient:
    def __init__(self, resp):
        self.resp = resp

    async def get(self, url, timeout=None, follow_redirects=None):
        return self.resp


async def test_auth_surface_okta_fingerprint():
    oidc = {"issuer": "https://login.example.com",
            "authorization_endpoint": "https://example.okta.com/oauth2/v1/authorize",
            "token_endpoint": "https://example.okta.com/oauth2/v1/token",
            "jwks_uri": "https://example.okta.com/oauth2/v1/keys"}
    out = await intel.auth_surface(_AuthClient(_AuthResp(200, oidc, "https://sso.example.com/x")),
                                   "sso.example.com")
    assert out["idp"] == "Okta"
    assert out["issuer"] == "https://login.example.com"
    assert "authorization_endpoint" in out["endpoints"]


async def test_auth_surface_entra_fingerprint():
    oidc = {"issuer": "https://login.microsoftonline.com/TENANT/v2.0",
            "authorization_endpoint": "https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize"}
    out = await intel.auth_surface(_AuthClient(_AuthResp(200, oidc, "x")), "login.example.com")
    assert out["idp"] == "Microsoft Entra ID"


async def test_auth_surface_unknown_idp_still_reports_endpoint():
    oidc = {"issuer": "https://idp.internal.example.com",
            "authorization_endpoint": "https://idp.internal.example.com/authorize"}
    out = await intel.auth_surface(_AuthClient(_AuthResp(200, oidc, "x")), "idp.example.com")
    assert out["idp"] is None                          # unrecognized IdP, but still surfaced
    assert out["issuer"] == "https://idp.internal.example.com"


async def test_auth_surface_empty_on_non_200_or_no_issuer():
    assert await intel.auth_surface(_AuthClient(_AuthResp(404, None, "x")), "x.com") == {}
    assert await intel.auth_surface(_AuthClient(_AuthResp(200, {"foo": "bar"}, "x")), "x.com") == {}


async def test_auth_surface_empty_on_exception():
    class _Boom:
        async def get(self, *a, **k):
            raise ConnectionError("refused")
    assert await intel.auth_surface(_Boom(), "x.com") == {}


def test_summarize_entry_points_includes_auth_surface():
    auth = [{"host": "sso.acme.com", "idp": "Okta", "issuer": "https://acme.okta.com"}]
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, auth)
    assert len(eps) == 1
    assert eps[0]["type"] == "auth-surface"
    assert eps[0]["severity"] == "info"
    assert "Okta" in eps[0]["summary"]
    assert eps[0]["attck"] == "T1590"


def test_summarize_entry_points_auth_surface_ranks_below_actionable():
    hosts = [Host("a.acme.com", takeover="unclaimed-service signature matched: s3")]
    auth = [{"host": "sso.acme.com", "idp": "Okta", "issuer": "i"}]
    eps = intel.summarize_entry_points(hosts, {}, [], {}, [], [], None, auth)
    # critical takeover first, info auth-surface last
    assert eps[0]["type"] == "subdomain-takeover"
    assert eps[-1]["type"] == "auth-surface"


def _whois_with_expiry(days_from_now):
    from datetime import datetime, timezone, timedelta
    exp = (datetime.now(timezone.utc) + timedelta(days=days_from_now)).isoformat()
    w = intel.empty_whois_entry()
    w.update({"expires": exp, "registrar": "Example Registrar"})
    return w


def test_summarize_entry_points_whois_expiring_within_30_days_is_medium():
    whois = {"acme.com": _whois_with_expiry(20)}
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois=whois)
    assert len(eps) == 1
    assert eps[0]["type"] == "whois-domain-expiring"
    assert eps[0]["severity"] == "medium"
    assert eps[0]["target"] == "acme.com"
    assert "Example Registrar" in eps[0]["summary"]
    assert eps[0]["attck"] == "T1590.001"


def test_summarize_entry_points_whois_expiring_within_7_days_is_high():
    whois = {"acme.com": _whois_with_expiry(3)}
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois=whois)
    assert len(eps) == 1
    assert eps[0]["type"] == "whois-domain-expiring"
    assert eps[0]["severity"] == "high"


def test_summarize_entry_points_whois_already_expired_is_high():
    whois = {"acme.com": _whois_with_expiry(-5)}
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois=whois)
    assert len(eps) == 1
    assert eps[0]["type"] == "whois-domain-expired"
    assert eps[0]["severity"] == "high"
    assert "takeover" in eps[0]["summary"].lower()


def test_summarize_entry_points_whois_far_future_expiry_no_finding():
    whois = {"acme.com": _whois_with_expiry(365)}
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois=whois)
    assert eps == []


def test_summarize_entry_points_whois_registrant_exposed_when_privacy_off():
    w = intel.empty_whois_entry()
    w.update({"privacy_protected": False, "registrant_name": "Jane Admin",
              "registrant_org": "Acme Inc"})
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois={"acme.com": w})
    assert len(eps) == 1
    assert eps[0]["type"] == "whois-registrant-exposed"
    assert eps[0]["severity"] == "info"
    assert "Jane Admin" in eps[0]["summary"]
    assert eps[0]["attck"] == "T1591"


def test_summarize_entry_points_whois_no_registrant_finding_when_privacy_on_or_unknown():
    private = intel.empty_whois_entry()
    private.update({"privacy_protected": True, "registrant_org": "Privacy Service"})
    unknown = intel.empty_whois_entry()
    unknown.update({"privacy_protected": None, "registrant_name": "Someone"})
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None,
                                       whois={"a.com": private, "b.com": unknown})
    assert eps == []


def test_summarize_entry_points_whois_defaults_to_none_backward_compatible():
    # Pre-existing positional arity (no whois arg) must still work, no WHOIS finding.
    assert intel.summarize_entry_points([], {"detected": False, "candidates": {}},
                                        [], {}, [], []) == []


def test_summarize_entry_points_whois_expired_ranks_above_registrant_exposed():
    expired = _whois_with_expiry(-1)
    exposed = intel.empty_whois_entry()
    exposed.update({"privacy_protected": False, "registrant_name": "Jane Admin"})
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None,
                                       whois={"a.com": expired, "b.com": exposed})
    assert [e["type"] for e in eps] == ["whois-domain-expired", "whois-registrant-exposed"]


def test_days_to_expiry_handles_naive_timezoneless_date():
    # Fallback WHOIS/VT tiers emit date-only strings like "2026-08-15"; these
    # parse to a naive datetime and must not raise/return None (regression).
    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).date().isoformat()
    days = intel._days_to_expiry(soon)
    assert days is not None
    assert 8 <= days <= 10


def test_summarize_entry_points_whois_finding_from_naive_date_only_expiry():
    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).date().isoformat()  # no tz
    w = intel.empty_whois_entry()
    w.update({"expires": soon, "registrar": "Namecheap", "source": "whois43"})
    eps = intel.summarize_entry_points([], {}, [], {}, [], [], None, None, whois={"acme.io": w})
    assert len(eps) == 1
    assert eps[0]["type"] == "whois-domain-expiring"
