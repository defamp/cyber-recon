"""Scan JS files for hardcoded secrets — passive regex-only check."""
import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import aiohttp

CONCURRENCY = 20
TIMEOUT = 10
JS_FETCH_LIMIT = 200  # don't try to fetch every JS, cap at this


PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(?i)aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key.{0,40}?[\"']([A-Za-z0-9/+=]{40})[\"']",
    "github_pat": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack_token": r"xox[abpr]-[0-9A-Za-z-]{10,48}",
    "google_api": r"AIza[0-9A-Za-z_\\-]{35}",
    "private_key": r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) (?:PRIVATE )?KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}",
    "generic_api_key": r"(?i)(?:api[_-]?key|apikey|secret)[\\\"'\\s:=]{1,5}[\"']([A-Za-z0-9_\\-]{16,64})[\"']",
}


@dataclass
class Finding:
    url: str
    pattern: str
    match: str


def _filter_js_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        try:
            path = urlparse(u).path.lower()
        except Exception:
            continue
        if path.endswith((".js", ".mjs", ".cjs")) and not path.endswith((".min.js.map",)):
            out.append(u)
            if len(out) >= JS_FETCH_LIMIT:
                break
    return out


async def _scan_url(session: aiohttp.ClientSession, url: str) -> list[Finding]:
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=TIMEOUT), allow_redirects=True
        ) as r:
            if r.status >= 400 or "javascript" not in (r.headers.get("Content-Type", "") or "").lower() and not url.endswith((".js", ".mjs", ".cjs")):
                # be lenient — only check content-type hint OR extension
                pass
            body = await r.text(errors="ignore")
    except Exception:
        return []
    findings: list[Finding] = []
    for name, pat in PATTERNS.items():
        for m in re.finditer(pat, body):
            findings.append(Finding(url=url, pattern=name, match=m.group(0)[:120]))
    return findings


async def scan_secrets(urls: list[str]) -> list[dict]:
    js_urls = _filter_js_urls(urls)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(u: str) -> list[Finding]:
        async with sem:
            return await _scan_url(session, u)

    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        results = await asyncio.gather(*(bounded(u) for u in js_urls))
    flat = [f for sub in results for f in sub]
    return [f.__dict__ for f in flat]
