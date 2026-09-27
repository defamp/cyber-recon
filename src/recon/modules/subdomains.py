"""Subdomain enumeration — passive only."""
import asyncio
import re
from typing import Iterable

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


async def _fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> list[str]:
    try:
        async with session.get(
            CRT_SH_URL.format(domain=domain), timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
            return [row.get("name_value", "") for row in data if row.get("name_value")]
    except Exception:
        return []


async def _fetch_hackertarget(session: aiohttp.ClientSession, domain: str) -> list[str]:
    try:
        async with session.get(
            HACKERTARGET_URL.format(domain=domain), timeout=aiohttp.ClientTimeout(total=20)
        ) as r:
            if r.status != 200:
                return []
            text = await r.text()
            return [line.split(",")[0] for line in text.splitlines() if "," in line]
    except Exception:
        return []


async def enumerate_subdomains(domain: str) -> list[str]:
    """Return sorted unique subdomains from crt.sh + HackerTarget."""
    domain = domain.lower().strip()
    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        crt_hosts, ht_hosts = await asyncio.gather(
            _fetch_crtsh(session, domain), _fetch_hackertarget(session, domain)
        )
    # crt.sh sometimes returns multi-line name_value
    flat: list[str] = []
    for blob in crt_hosts:
        flat.extend(re.split(r"\s+", blob))
    flat.extend(ht_hosts)
    return _extract_unique(domain, flat)
