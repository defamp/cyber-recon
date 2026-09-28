"""HTTP probing — fingerprint live hosts, headers, CORS, server tech."""

import asyncio
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field

import aiohttp
import dns.resolver  # type: ignore

from ..ratelimit import RateLimiter, scoped_get
from ..scope import Scope

CONCURRENCY = 30
TIMEOUT = 8
PROBE_SCHEMES = ("https", "http")  # try https first

# Response headers kept (lowercased) for the passive header audit.
AUDIT_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
    "x-powered-by",
    "x-aspnet-version",
)


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
    security_headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)


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


def _audit_subset(headers: dict[str, str]) -> dict[str, str]:
    lower = {k.lower(): v for k, v in headers.items()}
    return {name: lower[name] for name in AUDIT_HEADERS if name in lower}


def _set_cookies(headers) -> list[str]:
    # A plain dict collapses repeated Set-Cookie headers; aiohttp's multidict keeps them all.
    getall = getattr(headers, "getall", None)
    if getall is not None:
        return list(getall("Set-Cookie", []))
    value = headers.get("Set-Cookie") or headers.get("set-cookie")
    return [value] if value else []


async def _probe_one(
    session: aiohttp.ClientSession,
    host: str,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
) -> HostInfo | None:
    for scheme in PROBE_SCHEMES:
        url = f"{scheme}://{host}"
        try:
            async with scoped_get(
                session,
                url,
                scope=scope,
                limiter=limiter,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                ssl=False,
            ) as (r, final_url):
                headers = {k: v for k, v in r.headers.items()}
                body = await r.text(errors="ignore")
                excerpt = body[:2000].lower()
                title_match = await _extract_title(body)
                return HostInfo(
                    host=host,
                    url=final_url,
                    status=r.status,
                    server=headers.get("Server", ""),
                    title=title_match,
                    cors_acao=headers.get("Access-Control-Allow-Origin", ""),
                    cors_acac=headers.get("Access-Control-Allow-Credentials", ""),
                    technologies=_fingerprint_tech(headers, excerpt),
                    security_headers=_audit_subset(headers),
                    set_cookies=_set_cookies(r.headers),
                )
        except Exception:
            continue
    return None


async def _extract_title(body: str) -> str:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else ""


async def probe_targets(
    hosts: Iterable[str],
    *,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
) -> list[dict]:
    """DNS resolve + HTTP probe concurrently. Returns list of host dicts.

    Redirects are only followed while they stay inside ``scope``; requests are
    paced by ``limiter``.
    """
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(host: str) -> dict | None:
        async with sem:
            # dnspython is blocking; run it off the event loop so probes stay concurrent
            if not await asyncio.to_thread(_resolve, host):
                return None
            info = await _probe_one(session, host, scope, limiter)
            return asdict(info) if info else None

    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        results = await asyncio.gather(*(bounded(h) for h in hosts))
    return [r for r in results if r]
