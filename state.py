from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .common import *

# --------------------------------------------------------------------------- #
# On-disk cache + attack-surface diffing
# --------------------------------------------------------------------------- #
STATE_DIR = Path.home() / ".local" / "share" / "lrecon"


def _state_key(domains) -> str:
    return "_".join(sorted(domains)).replace("/", "_")[:120]


def load_prev_snapshot(domains) -> dict:
    p = STATE_DIR / f"{_state_key(domains)}.snapshot.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save_snapshot(domains, hosts) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    snap = {"ts": datetime.now(timezone.utc).isoformat(),
            "hosts": {h.subdomain: {"ips": h.ips, "ports": h.ports} for h in hosts}}
    (STATE_DIR / f"{_state_key(domains)}.snapshot.json").write_text(json.dumps(snap))


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


