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
    "google_api": r"AIza[0-9A-Za-z_-]{35}",
    "private_key": r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) (?:PRIVATE )?KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "stripe_key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "generic_api_key": r"(?i)(?:api[_-]?key|apikey|secret)[\"' :=]{1,5}[\"']([A-Za-z0-9_-]{16,64})[\"']",
}


# How likely a match is a real credential. Vendor-prefixed formats rarely
# false-positive; the generic keyword regex fires on config names, examples
# and minified code all the time.
CONFIDENCE: dict[str, str] = {
    "aws_access_key": "high",
    "github_pat": "high",
    "slack_token": "high",
    "google_api": "high",
    "private_key": "high",
    "stripe_key": "high",
    "aws_secret": "medium",
    "jwt": "medium",
    "generic_api_key": "low",
}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_URLS_PER_FINDING = 5


@dataclass
class Finding:
    url: str
    pattern: str
    match: str


def _filter_js_urls(urls: list[str]) -> list[str]:
    """JS URLs to fetch, one per host+path.

    Wayback often lists the same file many times with different cache-busting
    query strings or schemes; fetching each copy just repeats the findings.
    """
    out: list[str] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        try:
            parsed = urlparse(u)
        except Exception:
            continue
        path = parsed.path.lower()
        if path.endswith((".js", ".mjs", ".cjs")) and not path.endswith((".min.js.map",)):
            key = (parsed.netloc.lower().removesuffix(":80").removesuffix(":443"), parsed.path)
            if key in seen:
                continue
            seen.add(key)
            out.append(u)
            if len(out) >= JS_FETCH_LIMIT:
                break
    return out


async def _scan_url(session: aiohttp.ClientSession, url: str) -> list[Finding]:
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=TIMEOUT), allow_redirects=True
        ) as r:
            if r.status >= 400:
                return []
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
    return _group_findings(f for sub in results for f in sub)


def _group_findings(findings) -> list[dict]:
    """Merge identical matches found in several files into one entry,
    sorted most-confident first."""
    grouped: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f.pattern, f.match)
        entry = grouped.get(key)
        if entry is None:
            grouped[key] = {
                "url": f.url,
                "pattern": f.pattern,
                "match": f.match,
                "confidence": CONFIDENCE.get(f.pattern, "low"),
                "occurrences": 1,
                "urls": [f.url],
            }
            continue
        entry["occurrences"] += 1
        if f.url not in entry["urls"] and len(entry["urls"]) < MAX_URLS_PER_FINDING:
            entry["urls"].append(f.url)
    return sorted(
        grouped.values(),
        key=lambda e: (CONFIDENCE_ORDER[e["confidence"]], e["pattern"], e["match"]),
    )
