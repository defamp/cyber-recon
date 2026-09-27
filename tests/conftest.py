"""Shared fixtures."""

import aiohttp
import pytest


@pytest.fixture
def sample_hosts():
    return [
        "a.example.com",
        "b.example.com",
        "*.example.com",
        "unrelated.org",
        "foo.bar.example.com",
    ]


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Fail any test that lets a real aiohttp request through.

    Modules swallow request exceptions, so raising alone would go unnoticed;
    record the attempt and fail at teardown instead.
    """
    attempts: list[str] = []

    async def _blocked(self, method, url, *a, **kw):
        attempts.append(f"{method} {url}")
        raise RuntimeError(f"real network request in tests: {method} {url}")

    monkeypatch.setattr(aiohttp.ClientSession, "_request", _blocked)
    yield
    if attempts:
        pytest.fail(f"test made real network requests: {attempts}")


class FakeResp:
    def __init__(self, status=200, body=None, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body

    async def text(self, errors=None):
        return self._body if isinstance(self._body, str) else ""


class FakeSession:
    """Stand-in for aiohttp.ClientSession (respx only mocks httpx, not aiohttp).

    ``routes`` maps a URL prefix to a FakeResp, an Exception to raise, or a
    list of those consumed one per request (the last one repeats).
    """

    def __init__(self, routes):
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, *a, **kw):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kw):
        self.urls.append(url)
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                if isinstance(resp, list):
                    resp = resp.pop(0) if len(resp) > 1 else resp[0]
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise AssertionError(f"unexpected request: {url}")


@pytest.fixture
def fake_http(monkeypatch):
    """Install a FakeSession for all aiohttp.ClientSession users; returns it."""

    def install(routes):
        session = FakeSession(routes)
        monkeypatch.setattr(aiohttp, "ClientSession", session)
        return session

    return install
