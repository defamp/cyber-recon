"""Wayback Machine CDX endpoint discovery."""

import aiohttp

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"


async def fetch_wayback_urls(domain: str) -> list[str]:
    url = WAYBACK_CDX.format(domain=domain)
    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
    except Exception:
        return []
    if not data or len(data) < 2:
        return []
    # first row is the header, skip
    rows = data[1:]
    return sorted({row[0] for row in rows if row and row[0]})
