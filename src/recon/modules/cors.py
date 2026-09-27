"""CORS reflection tester — sends random Origin, checks if ACAO reflects it.

Active in the sense it issues HTTP requests with custom Origin header,
but no exploitation — purely defensive observation.
"""

import asyncio
import random
import string

import aiohttp

PROBE_ORIGINS = [
    "https://evil.example",
    "https://attacker.test",
    "null",
    "https://",
]

CONCURRENCY = 20
TIMEOUT = 8


def _rand_origin() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase, k=10))  # nosec B311
    return f"https://probe-{suffix}.example"


async def _test_origin(
    session: aiohttp.ClientSession, url: str, origin: str
) -> tuple[str, str, bool]:
    """Returns (origin, acao_header, reflects_origin)."""
    try:
        async with session.get(
            url,
            headers={"Origin": origin},
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            allow_redirects=False,
        ) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            reflects = acao == origin or acao == "*"
            return (origin, acao, reflects)
    except Exception:
        return (origin, "", False)


async def check_cors_reflection(hosts: list[dict]) -> dict[str, dict]:
    """For each live host, test if it reflects arbitrary Origin.

    Returns: {host: {"reflects": bool, "acao": str, "tested_origin": str}}
    """
    if not hosts:
        return {}

    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(h: dict) -> tuple[str, dict]:
        url = h.get("url")
        if not url:
            return h.get("host", ""), {"reflects": False, "acao": "", "tested_origin": ""}
        origin = _rand_origin()
        async with sem:
            tested, acao, reflects = await _test_origin(session, url, origin)
        return h.get("host", ""), {
            "reflects": reflects,
            "acao": acao,
            "tested_origin": tested,
        }

    headers = {"User-Agent": "cyber-recon/0.1 (+cors-probe)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        pairs = await asyncio.gather(*(bounded(h) for h in hosts))
    return {host: data for host, data in pairs}
