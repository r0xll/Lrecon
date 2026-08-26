from __future__ import annotations
from . import cache as _cache
from .cache import cached

# --------------------------------------------------------------------------- #
# Real-world exploitability signals for CVE ranking (both keyless).
#
#   * CISA KEV — the catalog of vulnerabilities *known to be exploited in the
#     wild*. Membership is the strongest "work this first" signal there is,
#     stronger than a high CVSS or even a public PoC.
#   * EPSS (FIRST.org) — a 0..1 probability that a CVE will be exploited in the
#     next 30 days. Turns a flat CVSS list into a likelihood ranking.
# --------------------------------------------------------------------------- #

CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_BATCH = 100                       # bounded so the query string stays sane


async def load_kev(client) -> set:
    """The CISA KEV catalog as a set of CVE IDs. Empty set on any failure
    (treated as "unknown", never as "not exploited"). Disk-cached (the catalog
    is ~1MB and changes about daily)."""
    async def _fetch():
        try:
            r = await client.get(CISA_KEV_URL, timeout=30)
            if r.status_code == 200:
                data = r.json() or {}
                return sorted({v.get("cveID") for v in data.get("vulnerabilities", [])
                               if v.get("cveID")})
        except Exception:
            pass
        return []
    return set(await cached("kev", "catalog", _fetch))


async def epss_scores(client, cve_ids) -> dict:
    """`{cve_id: epss_probability}` from FIRST.org, bulk-queried in batches.

    Missing ids simply aren't in the result (EPSS has no score for every CVE).
    A failed batch is skipped, not fatal — partial data still ranks.
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c]
    out, missing = {}, []
    # Serve per-CVE from disk cache; only the misses need a network batch.
    for cid in ids:
        v = _cache.get("epss", cid)
        if v is not None:
            out[cid] = v
        else:
            missing.append(cid)
    for i in range(0, len(missing), _EPSS_BATCH):
        batch = missing[i:i + _EPSS_BATCH]
        try:
            r = await client.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
            if r.status_code != 200:
                continue
            for row in (r.json() or {}).get("data", []):
                cid = row.get("cve")
                try:
                    val = float(row.get("epss"))
                except (TypeError, ValueError):
                    continue
                out[cid] = val
                _cache.put("epss", cid, val)
        except Exception:
            continue
    return out
