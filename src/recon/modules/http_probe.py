"""HTTP probing — fingerprint live hosts, headers, CORS, server tech."""

import asyncio
from collections.abc import Iterable
from dataclasses import asdict, dataclass

import aiohttp
import dns.resolver  # type: ignore

CONCURRENCY = 30
TIMEOUT = 8
PROBE_SCHEMES = ("https", "http")  # try https first


@dataclass
class HostInfo:
    host: str
    url: str
    status: int
    server: str
    title: str
    cors_acao: str
    cors_acac: str
    technologies: list[str]


def _resolve(host: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=5)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def _fingerprint_tech(headers: dict[str, str], body_excerpt: str) -> list[str]:
    tech: list[str] = []
    sigs = {
        "server": "Server",
        "powered-by": "X-Powered-By",
        "aspnet": "X-AspNet-Version",
        "wp": "X-WP-Generator",
        "drupal": "X-Drupal-Cache",
        "cloudflare": "CF-RAY",
        "akamai": "X-Akamai-Request-ID",
        "aws": "X-Amz-Request-Id",
        "nginx": "nginx",
        "apache": "Apache",
        "iis": "IIS",
    }
    for name, hdr in sigs.items():
        v = headers.get(hdr) or headers.get(hdr.lower())
        if v:
            tech.append(f"{name}:{v.split('/')[0].strip()}")
    if "wp-content" in body_excerpt or "wp-includes" in body_excerpt:
        tech.append("wordpress")
    if "drupal.settings" in body_excerpt:
        tech.append("drupal")
    if "csrfmiddlewaretoken" in body_excerpt:
        tech.append("django")
    return sorted(set(tech))


async def _probe_one(session: aiohttp.ClientSession, host: str) -> HostInfo | None:
    for scheme in PROBE_SCHEMES:
        url = f"{scheme}://{host}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
                ssl=False,
            ) as r:
                headers = {k: v for k, v in r.headers.items()}
                body = await r.text(errors="ignore")
                excerpt = body[:2000].lower()
                title_match = await _extract_title(body)
                return HostInfo(
                    host=host,
                    url=str(r.url),
                    status=r.status,
                    server=headers.get("Server", ""),
                    title=title_match,
                    cors_acao=headers.get("Access-Control-Allow-Origin", ""),
                    cors_acac=headers.get("Access-Control-Allow-Credentials", ""),
                    technologies=_fingerprint_tech(headers, excerpt),
                )
        except Exception:
            continue
    return None


async def _extract_title(body: str) -> str:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else ""


async def probe_targets(hosts: Iterable[str]) -> list[dict]:
    """DNS resolve + HTTP probe concurrently. Returns list of host dicts."""
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(host: str) -> dict | None:
        async with sem:
            if not _resolve(host):
                return None
            info = await _probe_one(session, host)
            return asdict(info) if info else None

    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        results = await asyncio.gather(*(bounded(h) for h in hosts))
    return [r for r in results if r]
