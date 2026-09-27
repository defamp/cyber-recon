"""Wayback Machine CDX endpoint discovery."""

import aiohttp

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"


async def fetch_wayback_urls(domain: str, errors: list[str] | None = None) -> list[str]:
    """Return unique archived URLs. Failures are appended to ``errors`` (if given)."""
    if errors is None:
        errors = []
    url = WAYBACK_CDX.format(domain=domain)
    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status != 200:
                    errors.append(f"wayback: http {r.status}")
                    return []
                data = await r.json(content_type=None)
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        errors.append(f"wayback: {detail}")
        return []
    if not isinstance(data, list):
        errors.append("wayback: unexpected response format")
        return []
    if len(data) < 2:
        return []
    # first row is the header, skip
    rows = data[1:]
    return sorted({row[0] for row in rows if isinstance(row, list) and row and row[0]})
