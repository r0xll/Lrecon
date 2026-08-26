from __future__ import annotations

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
    (treated as "unknown", never as "not exploited")."""
    try:
        r = await client.get(CISA_KEV_URL, timeout=30)
        if r.status_code == 200:
            data = r.json() or {}
            return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        pass
    return set()


async def epss_scores(client, cve_ids) -> dict:
    """`{cve_id: epss_probability}` from FIRST.org, bulk-queried in batches.

    Missing ids simply aren't in the result (EPSS has no score for every CVE).
    A failed batch is skipped, not fatal — partial data still ranks.
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c]
    out = {}
    for i in range(0, len(ids), _EPSS_BATCH):
        batch = ids[i:i + _EPSS_BATCH]
        try:
            r = await client.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
            if r.status_code != 200:
                continue
            for row in (r.json() or {}).get("data", []):
                cid = row.get("cve")
                try:
                    out[cid] = float(row.get("epss"))
                except (TypeError, ValueError):
                    pass
        except Exception:
            continue
    return out
