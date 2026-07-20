"""Unit tests for LRecon pure-logic and backend parsers (no network required)."""
import ipaddress

import lrecon
from lrecon import enrich, intel, state, backends
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
