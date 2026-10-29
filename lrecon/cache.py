from __future__ import annotations
import hashlib
import json
import time
from .state import STATE_DIR

# --------------------------------------------------------------------------- #
# On-disk TTL cache for third-party enrichment responses.
#
# IPinfo/Shodan/InternetDB/NVD/KEV/EPSS/VT answers change slowly but are
# re-fetched every run — and NVD's ~5-req/30s keyless limit makes a repeat run
# crawl. Cache them keyed by (namespace, arg) with a per-namespace TTL, so a
# re-scan of the same scope is near-instant. Live probes and banners are never
# cached (they must reflect the target now). --no-cache bypasses entirely.
# --------------------------------------------------------------------------- #

CACHE_DIR = STATE_DIR / "cache"

# Per-namespace default TTL in seconds. Slow-moving data (NVD, IP org) lives
# longer than volatile data (Shodan host state, KEV/EPSS daily feeds).
TTL = {
    "ipinfo": 7 * 86400,
    "shodan": 86400,
    "internetdb": 86400,
    "nvd": 7 * 86400,
    "nvd_id": 7 * 86400,
    "kev": 86400,
    "epss": 86400,
    "vt": 86400,
}
_DEFAULT_TTL = 86400

# Off until the application opts in (the CLI calls configure()). A library
# import — and every unit test — therefore gets the old fetch-every-time
# behaviour and never touches the shared on-disk cache.
_enabled = False
_ttl_override = None                       # seconds, or None to use per-namespace TTL
_stats = {"hit": 0, "miss": 0}


def configure(enabled: bool = True, ttl_override: int | None = None) -> None:
    """Set global cache behaviour for the run and reset the hit/miss counters."""
    global _enabled, _ttl_override
    _enabled, _ttl_override = enabled, ttl_override
    _stats["hit"] = _stats["miss"] = 0


def stats() -> dict:
    return dict(_stats)


def enabled() -> bool:
    return _enabled


def get(namespace: str, arg: str, ttl: int | None = None):
    """Public single-key read for batch callers (e.g. EPSS) that can't use the
    `cached()` wrapper. Counts a hit; a miss is the caller's to fetch."""
    if not _enabled:
        return None
    value = cache_get(namespace, arg, _effective_ttl(namespace, ttl))
    if value is not None:
        _stats["hit"] += 1
    else:
        _stats["miss"] += 1
    return value


def put(namespace: str, arg: str, value) -> None:
    if _enabled and value is not None:
        cache_set(namespace, arg, value)


def _path(namespace: str, arg: str):
    digest = hashlib.sha1(f"{namespace}\x00{arg}".encode()).hexdigest()
    return CACHE_DIR / f"{namespace}_{digest}.json"


def _effective_ttl(namespace: str, ttl: int | None) -> int:
    if _ttl_override is not None:
        return _ttl_override
    return ttl if ttl is not None else TTL.get(namespace, _DEFAULT_TTL)


def cache_get(namespace: str, arg: str, ttl: int):
    """The cached value for (namespace, arg) if present and within `ttl`, else
    None. A read error or an expired entry is a miss."""
    try:
        raw = json.loads(_path(namespace, arg).read_text())
    except Exception:
        return None
    if time.time() - raw.get("ts", 0) > ttl:
        return None
    return raw.get("value")


def cache_set(namespace: str, arg: str, value) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _path(namespace, arg).write_text(json.dumps({"ts": time.time(), "value": value}))
    except Exception:
        pass                                # a cache write must never break a run


async def cached(namespace: str, arg: str, fetch, ttl: int | None = None):
    """Return a disk-cached value for (namespace, arg), else run `fetch` (a
    zero-arg async callable), store a **truthy** result, and return it.

    Only truthy results are cached: a failed or empty fetch must not poison the
    cache and suppress a real answer on the next run. When caching is disabled
    (`--no-cache`), `fetch` always runs and nothing is stored.
    """
    if not _enabled:
        return await fetch()
    eff = _effective_ttl(namespace, ttl)
    hit = cache_get(namespace, arg, eff)
    if hit is not None:
        _stats["hit"] += 1
        return hit
    _stats["miss"] += 1
    value = await fetch()
    if value:
        cache_set(namespace, arg, value)
    return value
