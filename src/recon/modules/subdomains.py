"""Subdomain enumeration — passive only.

Every source queries a third-party dataset; nothing is sent to the target.
Optional API keys are read from the environment (see ``API_KEY_ENV``).
"""

import asyncio
import os
import re
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import urlparse

import aiohttp

CRT_SH_URL = "https://crt.sh/?q=%25{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"

# Optional keys: sources work without them, but with lower quotas.
API_KEY_ENV = {
    "certspotter": "CERTSPOTTER_API_KEY",
    "otx": "OTX_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
}

Fetcher = Callable[[aiohttp.ClientSession, str, list[str]], Awaitable[list[str]]]


def _extract_unique(domain: str, hosts: Iterable[str]) -> list[str]:
    suffix = "." + domain.lower()
    seen: set[str] = set()
    for h in hosts:
        h = h.strip().lower().lstrip("*.")
        if h.endswith(suffix) and h not in seen and "*" not in h:
            seen.add(h)
    return sorted(seen)


def _describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


async def _get_json(
    session: aiohttp.ClientSession,
    name: str,
    url: str,
    errors: list[str],
    *,
    timeout: int = 30,
    headers: dict[str, str] | None = None,
):
    """GET + parse JSON; on any failure record ``name: reason`` and return None."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout), headers=headers or {}
        ) as r:
            if r.status != 200:
                hint = " (rate limited — set an API key?)" if r.status == 429 else ""
                errors.append(f"{name}: http {r.status}{hint}")
                return None
            return await r.json(content_type=None)
    except Exception as exc:
        errors.append(f"{name}: {_describe(exc)}")
        return None


def _key_header(source: str, header: str, prefix: str = "") -> dict[str, str]:
    key = os.environ.get(API_KEY_ENV[source], "").strip()
    return {header: f"{prefix}{key}"} if key else {}


async def _fetch_crtsh(session: aiohttp.ClientSession, domain: str, errors: list[str]) -> list[str]:
    data = await _get_json(session, "crt.sh", CRT_SH_URL.format(domain=domain), errors)
    if data is None:
        return []
    if not isinstance(data, list):
        errors.append("crt.sh: unexpected response format")
        return []
    names = [row["name_value"] for row in data if isinstance(row, dict) and row.get("name_value")]
    # crt.sh sometimes returns multi-line name_value
    return [h for blob in names for h in re.split(r"\s+", blob)]


async def _fetch_hackertarget(
    session: aiohttp.ClientSession, domain: str, errors: list[str]
) -> list[str]:
    try:
        async with session.get(
            HACKERTARGET_URL.format(domain=domain), timeout=aiohttp.ClientTimeout(total=20)
        ) as r:
            if r.status != 200:
                errors.append(f"hackertarget: http {r.status}")
                return []
            text = await r.text()
    except Exception as exc:
        errors.append(f"hackertarget: {_describe(exc)}")
        return []
    hosts = [line.split(",")[0] for line in text.splitlines() if "," in line]
    # HackerTarget reports quota/input errors as a 200 with a plain-text message
    if not hosts and text.strip() and "no records found" not in text.lower():
        errors.append(f"hackertarget: {text.strip()[:120]}")
    return hosts


async def _fetch_certspotter(
    session: aiohttp.ClientSession, domain: str, errors: list[str]
) -> list[str]:
    # First page only: unauthenticated quotas are small, and one page already
    # covers the most recent issuances.
    data = await _get_json(
        session,
        "certspotter",
        CERTSPOTTER_URL.format(domain=domain),
        errors,
        headers=_key_header("certspotter", "Authorization", "Bearer "),
    )
    if data is None:
        return []
    if not isinstance(data, list):
        errors.append("certspotter: unexpected response format")
        return []
    return [
        name
        for row in data
        if isinstance(row, dict)
        for name in row.get("dns_names") or []
        if isinstance(name, str)
    ]


async def _fetch_otx(session: aiohttp.ClientSession, domain: str, errors: list[str]) -> list[str]:
    data = await _get_json(
        session,
        "otx",
        OTX_URL.format(domain=domain),
        errors,
        headers=_key_header("otx", "X-OTX-API-KEY"),
    )
    if data is None:
        return []
    rows = data.get("passive_dns") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        errors.append("otx: unexpected response format")
        return []
    return [
        r["hostname"] for r in rows if isinstance(r, dict) and isinstance(r.get("hostname"), str)
    ]


async def _fetch_urlscan(
    session: aiohttp.ClientSession, domain: str, errors: list[str]
) -> list[str]:
    data = await _get_json(
        session,
        "urlscan",
        URLSCAN_URL.format(domain=domain),
        errors,
        headers=_key_header("urlscan", "API-Key"),
    )
    if data is None:
        return []
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        errors.append("urlscan: unexpected response format")
        return []
    hosts: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        for part in ("page", "task"):
            value = (r.get(part) or {}).get("domain")
            if isinstance(value, str):
                hosts.append(value)
    return hosts


SOURCES: dict[str, Fetcher] = {
    "crtsh": _fetch_crtsh,
    "hackertarget": _fetch_hackertarget,
    "certspotter": _fetch_certspotter,
    "otx": _fetch_otx,
    "urlscan": _fetch_urlscan,
}


def hosts_from_urls(domain: str, urls: Iterable[str]) -> list[str]:
    """Subdomains seen in already-collected URLs (e.g. Wayback) — no new requests."""
    hosts = []
    for u in urls:
        try:
            host = urlparse(u).hostname
        except ValueError:
            continue
        if host:
            hosts.append(host)
    return _extract_unique(domain, hosts)


async def enumerate_subdomains(
    domain: str,
    errors: list[str] | None = None,
    *,
    sources: Iterable[str] | None = None,
    stats: dict[str, int] | None = None,
) -> list[str]:
    """Return sorted unique subdomains from the selected passive sources.

    Source failures are appended to ``errors`` (if given) instead of being
    silently treated as "no results". ``stats`` (if given) receives the number
    of in-domain hosts each source returned.
    """
    if errors is None:
        errors = []
    names = list(sources) if sources is not None else list(SOURCES)
    unknown = [n for n in names if n not in SOURCES]
    if unknown:
        raise ValueError(f"unknown subdomain source(s): {unknown} (known: {sorted(SOURCES)})")
    domain = domain.lower().strip()
    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        per_source = await asyncio.gather(
            *(SOURCES[name](session, domain, errors) for name in names)
        )
    found: set[str] = set()
    for name, hosts in zip(names, per_source, strict=True):
        unique = _extract_unique(domain, hosts)
        if stats is not None:
            stats[name] = len(unique)
        found.update(unique)
    return sorted(found)
