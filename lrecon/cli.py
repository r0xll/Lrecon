from __future__ import annotations
import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .common import log, load_keys, DEFAULT_RESOLVERS, TOP_PORTS, _HAVE_DNS
from .core import run
from .report import write_markdown, write_html, write_live_hosts, write_csv, screenshot_hosts
from .backends import available_backends
from . import backends

def main() -> None:
    ap = argparse.ArgumentParser(description="LRecon (Let's Recon) v3.2 — external recon (authorized use only)")
    ap.add_argument("domains", nargs="*", help="root domain(s) in scope")
    ap.add_argument("--check-backends", action="store_true",
                    help="validate optional backends (ProjectDiscovery tools + psql) + "
                         "parser mapping, then exit")
    ap.add_argument("--check-active", action="store_true",
                    help="with --check-backends: let naabu/nuclei test-scan scanme.nmap.org")
    ap.add_argument("--passive-only", action="store_true",
                    help="OSINT sources + host lookup only; no resolution/HTTP/portscan")
    ap.add_argument("--no-cf-origin", action="store_true",
                    help="disable Cloudflare origin-IP discovery")
    ap.add_argument("--active-ports", action="store_true",
                    help="async TCP connect scan of common ports (aggressive; ROE-gated)")
    ap.add_argument("--ports", help="comma-separated ports for --active-ports")
    ap.add_argument("--asn-expand", action="store_true",
                    help="expand scope via ASN->netblocks + reverse-DNS sweep (aggressive)")
    ap.add_argument("--asn-cap", type=int, default=4096, help="max PTR lookups for --asn-expand")
    ap.add_argument("--buckets", action="store_true", help="cloud bucket permutation enum")
    ap.add_argument("--bucket-keywords", help="extra comma-separated bucket keywords")
    ap.add_argument("--nvd", action="store_true", help="resolve CPEs to CVEs via NVD (slow)")
    ap.add_argument("--nvd-max-cves", type=int, default=25,
                    help="per-host cap on bare Shodan/InternetDB CVE IDs resolved via NVD "
                         "for CVSS/severity/description (default 25; raise for hosts with many "
                         "reported CVEs at the cost of more rate-limited NVD requests)")
    ap.add_argument("--nuclei", action="store_true",
                    help="run nuclei templated vuln scan on live hosts (needs nuclei binary)")
    ap.add_argument("--nuclei-severity", help="min nuclei severity (e.g. medium,high,critical)")
    ap.add_argument("--no-pd", action="store_true",
                    help="force pure-Python/HTTP paths; ignore ProjectDiscovery binaries "
                         "and the psql-based crt.sh direct-DB accelerator")
    ap.add_argument("--diff", action="store_true", help="diff against previous run snapshot")
    ap.add_argument("--screenshots", action="store_true",
                    help="capture live-host screenshots (needs playwright)")
    ap.add_argument("--resolvers", help=f"comma-separated DNS servers (default {','.join(DEFAULT_RESOLVERS)})")
    ap.add_argument("--shodan-key", help="Shodan API key (else env/config)")
    ap.add_argument("--ipinfo-key", help="IPinfo token (else env/config)")
    ap.add_argument("--ask-keys", action="store_true", help="prompt for keys via getpass")
    ap.add_argument("--config", help="config json path (default ~/.config/lrecon/config.json)")
    ap.add_argument("-c", "--concurrency", type=int, default=50)
    ap.add_argument("--no-progress", action="store_true")
    ap.add_argument("-o", "--out", default="lrecon",
                    help="output basename — a UTC timestamp is appended so "
                         "reruns don't overwrite prior output (<basename>_YYYYMMDD_HHMMSS.*)")
    args = ap.parse_args()

    if args.check_backends:
        rows = asyncio.run(backends.selfcheck(active=args.check_active))
        w = max(len(r["tool"]) for r in rows)
        log("[i] backend self-check" + (" (active test-scan)" if args.check_active else ""))
        log(f"    {'TOOL'.ljust(w)}  PATH  RAN  PARSED  NOTE")
        for r in rows:
            log(f"    {r['tool'].ljust(w)}  "
                f"{'yes' if r['path'] else ' no'}   "
                f"{'yes' if r['ran'] else ' no'}  "
                f"{str(r['parsed']).rjust(6)}  {r['note']}")
        broken = [r for r in rows if r["path"] and not r["ran"]]
        if broken:
            log(f"[!] {len(broken)} backend(s) present but failed to run/parse — "
                "check binary version vs parser in backends.py")
        return

    if not args.domains:
        ap.error("provide at least one domain (or use --check-backends)")

    if args.active_ports and args.passive_only:
        ap.error("--active-ports conflicts with --passive-only")
    args.ports = [int(p) for p in args.ports.split(",")] if args.ports else TOP_PORTS

    if not _HAVE_DNS and not args.passive_only:
        log("[!] dnspython missing — install it or use --passive-only")

    keys = load_keys(args)
    log(f"[i] enrichment: ports/CVE via {'Shodan' if keys['shodan'] else 'InternetDB (keyless)'}"
        f" | ASN/org/rDNS via {'IPinfo' if keys['ipinfo'] else 'disabled'}"
        f" | github {'on' if keys['github'] else 'off'}"
        f" | hibp {'key' if keys['hibp'] else 'keyless'}")
    if args.no_pd:
        log("[i] backends: forced pure-Python (--no-pd)")
    else:
        bk = available_backends()
        active = [t for t, ok in bk.items() if ok]
        log(f"[i] optional backends: {', '.join(active) if active else 'none on PATH (pure-Python)'}")

    t0 = time.time()
    res = asyncio.run(run(args.domains, args, keys))
    hosts = res["hosts"]

    out_base = f"{args.out}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    json_path = f"{out_base}.json"
    md_path = f"{out_base}.md"
    html_path = f"{out_base}.html"
    live_path = f"{out_base}.live.txt"
    csv_path = f"{out_base}.targets.csv"

    full = {k: res[k] for k in ("cf", "email", "github", "buckets", "breach",
                                "asn", "favicon_pivots", "nuclei", "diff", "per_source",
                                "entry_points")}
    full["hosts"] = [h.to_dict() for h in hosts]
    Path(json_path).write_text(json.dumps(full, indent=2, default=str))
    write_markdown(hosts, args.domains, res, md_path)
    write_html(hosts, args.domains, res, html_path)
    n_live = write_live_hosts(hosts, live_path)
    write_csv(hosts, csv_path)

    outputs = [json_path, md_path, html_path, live_path, csv_path]
    if args.screenshots:
        urls = [l for l in Path(live_path).read_text().splitlines() if l]
        shot_dir = f"{out_base}_shots"
        n = asyncio.run(screenshot_hosts(urls, shot_dir))
        if n:
            outputs.append(shot_dir + "/")
            log(f"[+] {n} screenshot(s) -> {shot_dir}/")

    n_entry = len(res.get("entry_points") or [])
    log(f"[+] done in {time.time()-t0:.1f}s — {len(hosts)} hosts, {n_live} live URLs, "
        f"{n_entry} potential entry point(s)")
    log(f"[+] {'  '.join(outputs)}")



if __name__ == "__main__":
    main()
