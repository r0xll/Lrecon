from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .common import *

# --------------------------------------------------------------------------- #
# On-disk cache + attack-surface diffing
# --------------------------------------------------------------------------- #
STATE_DIR = Path.home() / ".local" / "share" / "lrecon"


def _state_key(domains, ip_targets=None) -> str:
    key = "_".join(sorted(domains))
    if ip_targets:
        # Fold the IP/CIDR scope into the key so IP-only runs don't all share one
        # empty-domain snapshot, and two runs on the same domain with different
        # IP scopes don't overwrite each other. Hashed rather than joined so a
        # large CIDR expansion stays a fixed-width, collision-safe suffix instead
        # of a truncated IP list. Domain-only runs keep their original key
        # byte-for-byte, so existing snapshots stay continuous.
        import hashlib
        digest = hashlib.sha1("_".join(sorted(ip_targets)).encode()).hexdigest()[:12]
        key = f"{key}_ip-{digest}" if key else f"ip-{digest}"
    return key.replace("/", "_")[:120]


def load_prev_snapshot(domains, ip_targets=None) -> dict:
    p = STATE_DIR / f"{_state_key(domains, ip_targets)}.snapshot.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save_snapshot(domains, hosts, ip_targets=None) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    snap = {"ts": datetime.now(timezone.utc).isoformat(),
            "hosts": {h.subdomain: {"ips": h.ips, "ports": h.ports} for h in hosts}}
    (STATE_DIR / f"{_state_key(domains, ip_targets)}.snapshot.json").write_text(json.dumps(snap))


def diff_snapshot(prev: dict, hosts) -> dict:
    prev_hosts = prev.get("hosts", {})
    cur = {h.subdomain: {"ips": h.ips, "ports": h.ports} for h in hosts}
    new_hosts = sorted(set(cur) - set(prev_hosts))
    gone_hosts = sorted(set(prev_hosts) - set(cur))
    new_ports = {}
    for sub in set(cur) & set(prev_hosts):
        added = set(cur[sub]["ports"]) - set(prev_hosts[sub]["ports"])
        if added:
            new_ports[sub] = sorted(added)
    return {"prev_ts": prev.get("ts"), "new_hosts": new_hosts,
            "gone_hosts": gone_hosts, "new_ports": new_ports}


