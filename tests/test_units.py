"""Unit tests for LRecon pure-logic and backend parsers (no network required)."""
import csv
import ipaddress
import tempfile
from pathlib import Path

import lrecon
from lrecon import enrich, intel, state, backends, sources, report
from lrecon.common import Host, CF_FALLBACK


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
    assert set(bk) == {"subfinder", "dnsx", "httpx", "naabu", "nuclei"}
    assert all(isinstance(v, bool) for v in bk.values())


# --------------------------------------------------------------------------- #
# Reporting: CSV target list
# --------------------------------------------------------------------------- #
def test_write_csv_includes_wildcard_flag_and_target_fields():
    hosts = [
        Host("a.x.com", ips=["1.2.3.4"], asn="AS15169", org="Google LLC",
             country="US", scheme="https", http_status=200, source={"crtsh"}),
        Host("wild.x.com", ips=["9.9.9.9"], wildcard=True, source={"seed"}),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "targets.csv"
        n = report.write_csv(hosts, str(path))
        assert n == 2
        rows = list(csv.DictReader(path.open()))
    assert rows[0]["subdomain"] == "a.x.com"
    assert rows[0]["ips"] == "1.2.3.4"
    assert rows[0]["org"] == "Google LLC"
    assert rows[0]["wildcard"] == ""
    assert rows[1]["subdomain"] == "wild.x.com"
    assert rows[1]["wildcard"] == "yes"
