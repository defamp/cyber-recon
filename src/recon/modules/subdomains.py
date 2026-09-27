"""Subdomain enumeration — passive only."""

import asyncio
import re
from collections.abc import Iterable

import aiohttp

CRT_SH_URL = "https://crt.sh/?q=%25{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"


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


async def _fetch_crtsh(session: aiohttp.ClientSession, domain: str, errors: list[str]) -> list[str]:
    try:
        async with session.get(
            CRT_SH_URL.format(domain=domain), timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            if r.status != 200:
                errors.append(f"crt.sh: http {r.status}")
                return []
            data = await r.json(content_type=None)
    except Exception as exc:
        errors.append(f"crt.sh: {_describe(exc)}")
        return []
    if not isinstance(data, list):
        errors.append("crt.sh: unexpected response format")
        return []
    return [row["name_value"] for row in data if isinstance(row, dict) and row.get("name_value")]


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


async def enumerate_subdomains(domain: str, errors: list[str] | None = None) -> list[str]:
    """Return sorted unique subdomains from crt.sh + HackerTarget.

    Source failures are appended to ``errors`` (if given) instead of being
    silently treated as "no results".
    """
    if errors is None:
        errors = []
    domain = domain.lower().strip()
    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        crt_hosts, ht_hosts = await asyncio.gather(
            _fetch_crtsh(session, domain, errors), _fetch_hackertarget(session, domain, errors)
        )
    # crt.sh sometimes returns multi-line name_value
    flat: list[str] = []
    for blob in crt_hosts:
        flat.extend(re.split(r"\s+", blob))
    flat.extend(ht_hosts)
    return _extract_unique(domain, flat)
