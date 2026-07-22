"""Unit tests for LRecon pure-logic and backend parsers (no network required)."""
import csv
import ipaddress
import sys
import tempfile
from pathlib import Path

import pytest

import lrecon
from lrecon import enrich, intel, state, backends, sources, report, people, cli, core
from lrecon.common import Host, Person, CF_FALLBACK


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


def test_apply_ipinfo_records_per_ip_asn_for_multi_ip_hosts():
    h = Host("a.x.com", ips=["1.2.3.4", "5.6.7.8"])
    enrich.apply_ipinfo(h, {"org": "AS15169 Google LLC"}, "1.2.3.4")
    enrich.apply_ipinfo(h, {"org": "AS13335 Cloudflare"}, "5.6.7.8")
    assert h.ip_asn == {"1.2.3.4": "AS15169", "5.6.7.8": "AS13335"}
    assert h.asn == "AS13335"                    # scalar field: still last-IP-wins


def test_apply_ports_merges_and_tags_source():
    h = Host("a.x.com", ports=[80])
    enrich.apply_ports(h, {"ports": [443, 80], "vulns": ["CVE-2026-1"]}, "internetdb")
    assert h.ports == [80, 443]
    assert h.vulns == ["CVE-2026-1"]
    assert "internetdb" in h.enrich_src


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


def test_summarize_entry_points_includes_nvd_only_cves():
    # InternetDB gave CPEs but no vulns entries; --nvd found a critical CVE via CPE lookup.
    h = Host("legacy.x.com", nvd_cves=[{"id": "CVE-2026-9999", "cvss": 9.8}])
    cf = {"detected": False, "candidates": {}}
    eps = intel.summarize_entry_points([h], cf, [], {}, [], [])
    assert len(eps) == 1
    assert eps[0]["type"] == "known-cve"
    assert eps[0]["severity"] == "critical"
    assert "CVE-2026-9999" in eps[0]["summary"]


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
    res = await intel.cloudflare_origin_analysis(
        None, None, ["x.com"], hosts, {}, nets, active=False, resolver_ns=None)
    assert res["detected"] is True
    assert "x.com" in res["fronted"]
    assert "45.79.10.20" in res["candidates"]


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
def test_write_csv_has_subdomain_ips_and_per_ip_asn():
    hosts = [
        Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC",
             country="US", scheme="https", http_status=200, source={"crtsh"},
             ip_asn={"1.2.3.4": "AS15169"}),
        # multi-IP host, only one IP resolved to an ASN — asn column stays
        # positionally parallel to ips, blank where unresolved.
        Host("multi.x.com", ips=["9.9.9.9", "8.8.8.8"], wildcard=True, source={"seed"},
             ip_asn={"8.8.8.8": "AS15169"}),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        n = report.write_csv(hosts, str(path))
        assert n == 2
        rows = list(csv.DictReader(path.open()))
    assert list(rows[0].keys()) == ["subdomain", "ips", "asn"]
    assert rows[0]["subdomain"] == "a.x.com"
    assert rows[0]["ips"] == "1.2.3.4"
    assert rows[0]["asn"] == "AS15169"
    assert rows[1]["subdomain"] == "multi.x.com"
    assert rows[1]["ips"] == "9.9.9.9, 8.8.8.8"
    assert rows[1]["asn"] == ", AS15169"          # blank for 9.9.9.9, resolved for 8.8.8.8


def test_write_csv_single_ip_host_falls_back_to_scalar_asn():
    # ip_asn wasn't populated (e.g. a caller of apply_ipinfo() that omitted
    # the optional ip arg), but h.asn is known and unambiguous for one IP.
    h = Host("a.x.com", ips=["1.2.3.4"], asn="AS15169")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        report.write_csv([h], str(path))
        rows = list(csv.DictReader(path.open()))
    assert rows[0]["asn"] == "AS15169"


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
