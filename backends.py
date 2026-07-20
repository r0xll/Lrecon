"""
ProjectDiscovery backend wiring.

Each function is an OPTIONAL native accelerator. If the binary isn't on PATH the
function returns None and the caller falls back to the pure-Python path. Nothing
here is required to run lrecon.

Tools: subfinder (passive enum), dnsx (mass resolution), httpx (HTTP probe + tech
fingerprint + favicon), naabu (port scan), nuclei (templated vuln scan).
"""
from __future__ import annotations
import asyncio
import json
import shutil

from .common import log


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def is_pd_httpx() -> bool:
    """The Python `httpx` lib also ships an `httpx` CLI — disambiguate from PD's."""
    if not have("httpx"):
        return False
    try:
        import subprocess
        out = subprocess.run(["httpx", "-version"], capture_output=True, text=True,
                             timeout=10)
        return "projectdiscovery" in (out.stdout + out.stderr).lower()
    except Exception:
        return False


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
    if not is_pd_httpx():
        return None
    inp = "\n".join(hosts).encode()
    out = await _run(["httpx", "-json", "-silent", "-td", "-title", "-status-code",
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
    cmd = ["nuclei", "-silent", "-jsonl", "-rate-limit", str(rate), "-no-color"]
    if severity:
        cmd += ["-severity", severity]
    out = await _run(cmd, stdin=inp, timeout=1800)
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


def available_backends() -> dict:
    return {"subfinder": have("subfinder"), "dnsx": have("dnsx"),
            "httpx": is_pd_httpx(), "naabu": have("naabu"), "nuclei": have("nuclei")}


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

    return out
