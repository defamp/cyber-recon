"""Global request pacing and scope-aware redirect following for target traffic.

Only requests that reach the target go through here (HTTP probe, CORS probe,
JS fetches). Third-party passive sources (crt.sh, HackerTarget, Wayback) are
not paced by this limiter.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

if TYPE_CHECKING:
    import aiohttp

    from .scope import Scope

MAX_REDIRECTS = 5


class RateLimiter:
    """Evenly spaced requests: at most ``rate`` per second across all callers."""

    def __init__(self, rate: float | None = None):
        self.rate = rate if rate and rate > 0 else None
        self._interval = 1.0 / self.rate if self.rate else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = self._next
            self._next = now + self._interval


@asynccontextmanager
async def scoped_get(
    session: aiohttp.ClientSession,
    url: str,
    *,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
    max_redirects: int = MAX_REDIRECTS,
    **kwargs: Any,
) -> AsyncIterator[tuple[Any, str]]:
    """GET ``url``, following redirects only while they stay in scope.

    Yields ``(response, final_url)``. A redirect that leaves scope is not
    followed: the 3xx response itself is yielded, so callers still see the
    in-scope host answered.
    """
    for _ in range(max_redirects + 1):
        if limiter:
            await limiter.wait()
        async with session.get(url, allow_redirects=False, **kwargs) as r:
            location = r.headers.get("Location") if 300 <= r.status < 400 else None
            if not location:
                yield r, url
                return
            nxt = urljoin(url, location)
            if scope is not None and not scope.url_in_scope(nxt):
                yield r, url
                return
        url = nxt
    raise RuntimeError(f"too many redirects (>{max_redirects})")
