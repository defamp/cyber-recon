from recon.modules.http_probe import _fingerprint_tech


def test_fingerprint_wordpress():
    body = '<html><body><script src="/wp-content/themes/foo.js"></script></body></html>'
    techs = _fingerprint_tech({}, body.lower())
    assert "wordpress" in techs


def test_fingerprint_drupal_settings():
    body = 'drupal.settings = {"path":{"baseUrl":"\\/"},"user":{"uid":0}}'
    techs = _fingerprint_tech({}, body.lower())
    assert "drupal" in techs


def test_fingerprint_django_csrf():
    body = '<input name="csrfmiddlewaretoken" value="abc">'
    techs = _fingerprint_tech({}, body.lower())
    assert "django" in techs


def test_fingerprint_server_header():
    techs = _fingerprint_tech({"Server": "nginx/1.25.1"}, "")
    assert any("nginx" in t for t in techs)


def test_fingerprint_cloudflare():
    techs = _fingerprint_tech({"CF-RAY": "abc123"}, "")
    assert any("cloudflare" in t for t in techs)


def test_fingerprint_empty():
    assert _fingerprint_tech({}, "") == []


def test_fingerprint_dedup():
    body = "wp-content wp-includes"
    techs = _fingerprint_tech({}, body.lower())
    assert techs.count("wordpress") == 1


def _fake_getaddrinfo(result=None, exc=None):
    async def getaddrinfo(host, port, **kw):
        if exc:
            raise exc
        return result

    return getaddrinfo


def test_resolve_reports_dns_failure(monkeypatch):
    import asyncio
    import socket

    from recon.modules import http_probe

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop,
            "getaddrinfo",
            _fake_getaddrinfo(exc=socket.gaierror(-2, "Name or service not known")),
        )
        return await http_probe._resolve("nope.x.com")

    assert asyncio.run(run()) == ([], "DNS: Name or service not known")


def test_resolve_returns_addresses(monkeypatch):
    import asyncio
    import socket

    from recon.modules import http_probe

    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
    ]

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", _fake_getaddrinfo(result=infos))
        return await http_probe._resolve("a.x.com")

    assert asyncio.run(run()) == (["1.2.3.4", "::1"], "")


def test_probe_records_failure_reasons(fake_http, monkeypatch):
    import asyncio

    import aiohttp

    from recon.modules import http_probe

    async def fake_resolve(host):
        if host == "gone.x.com":
            return [], "DNS: Name or service not known"
        return ["1.2.3.4"], ""

    monkeypatch.setattr(http_probe, "_resolve", fake_resolve)
    fake_http(
        {
            "https://up.x.com": aiohttp.ClientConnectionError("connection refused"),
            "http://up.x.com": TimeoutError(),
        }
    )
    failures: dict[str, str] = {}
    alive = asyncio.run(http_probe.probe_targets(["up.x.com", "gone.x.com"], failures))
    assert alive == []
    assert failures == {
        "gone.x.com": "DNS: Name or service not known",
        "up.x.com": "https: ClientConnectionError: connection refused; http: timed out after 8s",
    }
