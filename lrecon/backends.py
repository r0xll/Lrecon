"""
External binary backend wiring (ProjectDiscovery tools + psql).

Each function is an OPTIONAL native accelerator. If the binary isn't on PATH the
function returns None and the caller falls back to the pure-Python path. Nothing
here is required to run lrecon.

Tools: subfinder (passive enum), dnsx (mass resolution), httpx (HTTP probe + tech
fingerprint + favicon), naabu (port scan), nuclei (templated vuln scan), psql
(direct query against crt.sh's public Postgres replica — bypasses its flaky
HTTP/JSON frontend; not a ProjectDiscovery tool, but same optional-accelerator
pattern).
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
from pathlib import Path

from .common import log


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


_HTTPX_NAMES = ("httpx", "httpx-pd", "pdhttpx")


def _candidate_httpx_paths() -> list:
    """
    Every plausible httpx executable, so we can pick the ProjectDiscovery one even
    when a venv's `httpx` (the Python library's CLI stub) shadows it on PATH.

    Order: explicit override, then PATH dirs, then Go install locations.
    Set LRECON_HTTPX to a full path to force a specific binary.
    """
    override = os.environ.get("LRECON_HTTPX")
    if override:
        return [override]

    dirs = list(os.environ.get("PATH", "").split(os.pathsep))
    if os.environ.get("GOBIN"):
        dirs.append(os.environ["GOBIN"])
    for g in os.environ.get("GOPATH", "").split(os.pathsep):
        if g:
            dirs.append(str(Path(g) / "bin"))
    dirs.append(str(Path.home() / "go" / "bin"))

    out, seen = [], set()
    for d in dirs:
        if not d:
            continue
        for name in _HTTPX_NAMES:
            p = Path(d) / name
            key = str(p)
            if key not in seen and p.is_file() and os.access(p, os.X_OK):
                seen.add(key)
                out.append(key)
    return out


def pd_httpx_bin() -> str | None:
    """Full path to the ProjectDiscovery httpx binary, or None. Verified via -version
    so the Python `httpx` CLI stub is never mistaken for it — no renaming required."""
    import subprocess
    for path in _candidate_httpx_paths():
        try:
            out = subprocess.run([path, "-version"], capture_output=True,
                                 text=True, timeout=10)
            if "projectdiscovery" in (out.stdout + out.stderr).lower():
                return path
        except Exception:
            continue
    return None


def is_pd_httpx() -> bool:
    return pd_httpx_bin() is not None


async def _run(cmd: list, stdin: bytes | None = None, timeout: int = 900) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
        return out.decode(errors="ignore")
    except Exception as e:
        log(f"[!] backend {cmd[0]}: {e}")
        return ""


def _looks_like_nuclei_finding(line: str) -> bool:
    """A nuclei -jsonl result line, not a -stats status line or banner
    text — findings always carry both of these fields."""
    try:
        obj = json.loads(line)
    except Exception:
        return False
    return isinstance(obj, dict) and "template-id" in obj and "matched-at" in obj


async def _run_nuclei(cmd: list, stdin: bytes, timeout: int = 1800) -> str:
    """
    Like _run(), but streams progress live via log() instead of silently
    discarding it for the whole (possibly many-minutes-long) scan —
    nuclei's own periodic -stats status lines (duration/hosts/requests/rps)
    otherwise vanish into stderr, making a long scan look hung. Reads
    stdout line-by-line as results arrive: JSONL finding lines are
    collected and returned (same shape _run() would have returned, so
    nuclei_scan()'s existing _jsonl() parsing is unchanged); any other
    non-empty line, on stdout or stderr, is logged live instead — this
    covers -stats output landing on either stream without needing to
    assume which one nuclei uses.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    except Exception as e:
        log(f"[!] backend {cmd[0]}: {e}")
        return ""

    finding_lines = []

    async def feed_stdin():
        try:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
        finally:
            proc.stdin.close()

    async def pump_stdout():
        async for raw in proc.stdout:
            line = raw.decode(errors="ignore").strip()
            if not line:
                continue
            if _looks_like_nuclei_finding(line):
                finding_lines.append(line)
            else:
                log(f"    [nuclei] {line}")

    async def pump_stderr():
        async for raw in proc.stderr:
            line = raw.decode(errors="ignore").strip()
            if line:
                log(f"    [nuclei] {line}")

    try:
        await asyncio.wait_for(asyncio.gather(feed_stdin(), pump_stdout(), pump_stderr()),
                               timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        log(f"[!] backend {cmd[0]}: timed out after {timeout}s")
    except Exception as e:
        log(f"[!] backend {cmd[0]}: {e}")
    finally:
        if proc.returncode is None:
            await proc.wait()

    return "\n".join(finding_lines)


def _jsonl(text: str):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


# --------------------------------------------------------------------------- #
async def dnsx_resolve(subdomains) -> dict | None:
    """Mass A/AAAA/CNAME resolution. Returns {host: {a, aaaa, cname}} or None."""
    if not have("dnsx"):
        return None
    inp = "\n".join(subdomains).encode()
    out = await _run(["dnsx", "-json", "-silent", "-a", "-aaaa", "-cname", "-resp"],
                     stdin=inp)
    res = {}
    for j in _jsonl(out):
        host = (j.get("host") or "").lower()
        if not host:
            continue
        cname = j.get("cname") or []
        res[host] = {"a": j.get("a", []), "aaaa": j.get("aaaa", []),
                     "cname": (cname[0].rstrip(".").lower() if cname else None)}
    return res


async def httpx_probe(hosts) -> dict | None:
    """HTTP probe + tech fingerprint + favicon. Returns {host: {...}} or None."""
    binname = pd_httpx_bin()
    if not binname:
        return None
    inp = "\n".join(hosts).encode()
    out = await _run([binname, "-json", "-silent", "-td", "-title", "-status-code",
                      "-web-server", "-favicon", "-follow-redirects",
                      "-no-color", "-timeout", "10"], stdin=inp)
    res = {}
    for j in _jsonl(out):
        host = (j.get("input") or j.get("host") or "").lower()
        # strip scheme if httpx echoed a URL as input
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        if not host:
            continue
        url = j.get("url", "")
        res[host] = {
            "status": j.get("status_code"),
            "title": j.get("title"),
            "server": j.get("webserver"),
            "tech": j.get("tech", []),
            "favicon": j.get("favicon"),          # mmh3 hash (Shodan-compatible)
            "scheme": "https" if url.startswith("https") else "http",
            "final_url": url,
        }
    return res


async def naabu_scan(host: str, ports=None) -> list | None:
    if not have("naabu"):
        return None
    cmd = ["naabu", "-host", host, "-silent", "-json"]
    cmd += (["-p", ",".join(map(str, ports))] if ports else ["-top-ports", "100"])
    out = await _run(cmd, timeout=300)
    return sorted({j["port"] for j in _jsonl(out) if j.get("port")})


async def nuclei_scan(urls, severity=None, rate=150) -> list | None:
    if not have("nuclei") or not urls:
        return None
    inp = "\n".join(urls).encode()
    # -stats -stats-interval periodically emits scan-status lines (duration/
    # hosts/requests/rps) alongside -silent's normal findings-only output —
    # _run_nuclei() streams those live via log() so a long scan (up to the
    # 1800s timeout below) isn't a silent wait.
    cmd = ["nuclei", "-silent", "-jsonl", "-rate-limit", str(rate), "-no-color",
          "-stats", "-stats-interval", "5"]
    if severity:
        cmd += ["-severity", severity]
    out = await _run_nuclei(cmd, stdin=inp, timeout=1800)
    findings = []
    for j in _jsonl(out):
        info = j.get("info", {})
        findings.append({
            "host": j.get("host"),
            "template": j.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched": j.get("matched-at"),
            "cve": (info.get("classification", {}) or {}).get("cve-id"),
        })
    return findings


async def crtsh_psql(domain: str) -> list | None:
    """
    Direct query against crt.sh's public PostgreSQL replica (host crt.sh, port
    5432, read-only 'guest' account — documented by crt.sh itself), bypassing
    its notoriously flaky HTTP/JSON frontend entirely. Optional: only used if
    `psql` is on PATH; returns None (caller falls back to the HTTP path)
    otherwise, or if the query produced no usable output (covers both a
    connection failure and a genuinely empty result the same way — either
    way the HTTP path is cheap insurance).

    The domain is passed via psql's :'var' substitution (psql handles the SQL
    quoting/escaping), never string-interpolated into the query text.
    """
    if not have("psql"):
        return None
    query = ("SELECT DISTINCT ci.NAME_VALUE FROM certificate_and_identities ci "
             "WHERE ci.NAME_VALUE ILIKE :'pattern' AND ci.NAME_VALUE NOT ILIKE '%@%';")
    cmd = ["psql", "-h", "crt.sh", "-p", "5432", "-U", "guest", "-d", "certwatch",
          "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", f"pattern=%.{domain}",
          "-c", query]
    out = await _run(cmd, timeout=45)
    rows = [line.strip() for line in out.splitlines() if line.strip()]
    return rows or None


def available_backends() -> dict:
    return {"subfinder": have("subfinder"), "dnsx": have("dnsx"),
            "httpx": is_pd_httpx(), "naabu": have("naabu"), "nuclei": have("nuclei"),
            "psql (crt.sh)": have("psql")}


async def selfcheck(active: bool = False) -> list:
    """
    Validate each detected backend + confirm the parser mapping populates fields.
    Passive tools run against safe public targets; naabu/nuclei only version-check
    unless active=True (then they test-scan scanme.nmap.org, sanctioned for testing).
    """
    bk = available_backends()
    out = []

    def row(tool, path, ran, parsed, note):
        out.append({"tool": tool, "path": path, "ran": ran, "parsed": parsed, "note": note})

    # subfinder — passive
    if bk["subfinder"]:
        txt = await _run(["subfinder", "-silent", "-d", "hackerone.com"], timeout=120)
        n = len([l for l in txt.splitlines() if l.strip()])
        row("subfinder", True, n > 0, n, f"{n} subdomains parsed" if n else "ran, 0 parsed")
    else:
        row("subfinder", False, False, 0, "not on PATH")

    # dnsx — benign resolution
    if bk["dnsx"]:
        res = await dnsx_resolve(["example.com", "www.example.com"])
        ok = bool(res) and any(v["a"] for v in res.values())
        row("dnsx", True, res is not None, len(res or {}),
            "A records parsed OK" if ok else "ran but no A records — check parser keys")
    else:
        row("dnsx", False, False, 0, "not on PATH")

    # httpx — single benign GET
    if bk["httpx"]:
        res = await httpx_probe(["example.com"])
        d = (res or {}).get("example.com", {})
        ok = bool(d.get("status"))
        row("httpx", True, res is not None, len(res or {}),
            f"status={d.get('status')} tech={d.get('tech')} favicon={'yes' if d.get('favicon') else 'no'}"
            if ok else "ran but no fields — check parser keys")
    else:
        row("httpx", False, False, 0, "not on PATH")

    # naabu — active
    if bk["naabu"]:
        if active:
            ports = await naabu_scan("scanme.nmap.org", [22, 80, 443, 9929])
            row("naabu", True, ports is not None, len(ports or []),
                f"scanme.nmap.org open: {ports}")
        else:
            v = await _run(["naabu", "-version"], timeout=15)
            row("naabu", True, bool(v), 0, "binary OK (use --check-active to test-scan)")
    else:
        row("naabu", False, False, 0, "not on PATH")

    # nuclei — active
    if bk["nuclei"]:
        if active:
            f = await nuclei_scan(["https://scanme.nmap.org"], severity="info,low")
            row("nuclei", True, f is not None, len(f or []),
                f"{len(f or [])} finding(s) on scanme.nmap.org")
        else:
            v = await _run(["nuclei", "-version"], timeout=20)
            row("nuclei", True, bool(v), 0, "binary OK (use --check-active to test-scan)")
    else:
        row("nuclei", False, False, 0, "not on PATH")

    # psql (crt.sh direct-Postgres) — passive, read-only
    if bk["psql (crt.sh)"]:
        rows = await crtsh_psql("example.com")
        n = len(rows or [])
        row("psql (crt.sh)", True, rows is not None, n,
            f"{n} name(s) parsed" if rows else "ran but no rows — check connectivity/query")
    else:
        row("psql (crt.sh)", False, False, 0, "not on PATH")

    return out
