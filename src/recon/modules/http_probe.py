"""HTTP probing — fingerprint live hosts, headers, CORS, server tech."""

import asyncio
import socket
from collections.abc import Iterable
from dataclasses import asdict, dataclass

import aiohttp

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


DNS_TIMEOUT = 5


async def _resolve(host: str) -> tuple[list[str], str]:
    """Resolve via the system resolver, the same one aiohttp, curl and the
    browser use (so /etc/hosts, VPN and systemd-resolved setups behave the
    same). Returns (addresses, failure reason)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=DNS_TIMEOUT
        )
    except TimeoutError:
        return [], f"DNS: timed out after {DNS_TIMEOUT}s"
    except OSError as exc:
        return [], f"DNS: {exc.strerror or exc}"
    return sorted({info[4][0] for info in infos}), ""


def _describe(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return f"timed out after {TIMEOUT}s"
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


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


async def _probe_one(
    session: aiohttp.ClientSession, host: str, failures: dict[str, str]
) -> HostInfo | None:
    reasons: list[str] = []
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
        except Exception as exc:
            reasons.append(f"{scheme}: {_describe(exc)}")
            continue
    failures[host] = "; ".join(reasons)
    return None


async def _extract_title(body: str) -> str:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else ""


async def probe_targets(hosts: Iterable[str], failures: dict[str, str] | None = None) -> list[dict]:
    """DNS resolve + HTTP probe concurrently. Returns list of host dicts.

    Hosts that don't answer are recorded in ``failures`` (host -> reason).
    """
    if failures is None:
        failures = {}
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(host: str) -> dict | None:
        async with sem:
            addrs, reason = await _resolve(host)
            if not addrs:
                failures[host] = reason
                return None
            info = await _probe_one(session, host, failures)
            return asdict(info) if info else None

    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        results = await asyncio.gather(*(bounded(h) for h in hosts))
    return [r for r in results if r]
