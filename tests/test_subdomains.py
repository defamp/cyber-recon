from recon.modules.subdomains import _extract_unique


def test_extract_unique_strips_wildcards(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "*.example.com" not in result
    assert "*" not in "".join(result)


def test_extract_unique_filters_unrelated(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "unrelated.org" not in result


def test_extract_unique_keeps_subdomains(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "a.example.com" in result
    assert "foo.bar.example.com" in result


def test_extract_unique_dedupes():
    hosts = ["a.example.com", "a.example.com", "b.example.com"]
    result = _extract_unique("example.com", hosts)
    assert len(result) == 2


def test_extract_unique_lowercases():
    hosts = ["A.Example.COM"]
    result = _extract_unique("example.com", hosts)
    assert result == ["a.example.com"]


def test_extract_unique_empty():
    assert _extract_unique("example.com", []) == []


CRT = "https://crt.sh/"
HT = "https://api.hackertarget.com/"
CS = "https://api.certspotter.com/"


def test_crtsh_retries_then_succeeds(fake_http, monkeypatch):
    import asyncio

    from conftest import FakeResp

    from recon.modules import subdomains

    monkeypatch.setattr(subdomains, "RETRY_BACKOFF", 0)
    fake = fake_http(
        {
            CRT: [
                FakeResp(502),
                FakeResp(200, "<html>overloaded</html>"),
                FakeResp(200, [{"name_value": "a.x.com"}]),
            ],
            CS: FakeResp(200, []),
            HT: FakeResp(200, "no records found"),
        }
    )
    errors: list[str] = []
    result = asyncio.run(subdomains.enumerate_subdomains("x.com", errors))
    assert result == ["a.x.com"]
    assert errors == []
    assert sum(u.startswith(CRT) for u in fake.urls) == 3


def test_crtsh_reports_last_error_after_all_attempts(fake_http, monkeypatch):
    import asyncio

    from conftest import FakeResp

    from recon.modules import subdomains

    monkeypatch.setattr(subdomains, "RETRY_BACKOFF", 0)
    fake_http(
        {
            CRT: FakeResp(200, "<html>busy</html>"),
            CS: FakeResp(200, []),
            HT: FakeResp(200, "no records found"),
        }
    )
    errors: list[str] = []
    assert asyncio.run(subdomains.enumerate_subdomains("x.com", errors)) == []
    assert errors == ["crt.sh: response was not JSON: 'busy' (after 3 attempts)"]


def test_crtsh_query_matches_subdomains_only():
    from recon.modules.subdomains import CRT_SH_URL

    assert CRT_SH_URL.format(domain="x.com") == "https://crt.sh/?q=%25.x.com&output=json"


def test_crtsh_error_shows_what_the_page_said(fake_http, monkeypatch):
    import asyncio

    from conftest import FakeResp

    from recon.modules import subdomains

    monkeypatch.setattr(subdomains, "RETRY_BACKOFF", 0)
    page = "<html><head><title>502</title></head><body><h1>Too many requests</h1></body></html>"
    fake_http(
        {CRT: FakeResp(200, page), CS: FakeResp(200, []), HT: FakeResp(200, "no records found")}
    )
    errors: list[str] = []
    asyncio.run(subdomains.enumerate_subdomains("x.com", errors))
    assert errors == ["crt.sh: response was not JSON: '502 Too many requests' (after 3 attempts)"]


def test_certspotter_alone_still_finds_subdomains(fake_http, monkeypatch):
    """crt.sh down and HackerTarget out of quota: CertSpotter still answers."""
    import asyncio

    from conftest import FakeResp

    from recon.modules import subdomains

    monkeypatch.setattr(subdomains, "RETRY_BACKOFF", 0)
    fake_http(
        {
            CRT: FakeResp(502),
            CS: FakeResp(
                200, [{"dns_names": ["x.com", "www.x.com"]}, {"dns_names": ["*.api.x.com"]}]
            ),
            HT: FakeResp(200, "API count exceeded - Increase Quota with Membership"),
        }
    )
    errors: list[str] = []
    result = asyncio.run(subdomains.enumerate_subdomains("x.com", errors))
    assert result == ["api.x.com", "www.x.com"]
    assert errors == [
        "crt.sh: http 502 (after 3 attempts)",
        "hackertarget: API count exceeded - Increase Quota with Membership",
    ]


def test_certspotter_sends_token_when_configured(fake_http, monkeypatch):
    import asyncio

    from conftest import FakeResp

    from recon.modules import subdomains

    seen = {}
    fake = fake_http(
        {
            CRT: FakeResp(200, []),
            CS: FakeResp(200, []),
            HT: FakeResp(200, "no records found"),
        }
    )
    orig_get = fake.get

    def get(url, **kw):
        if url.startswith(CS):
            seen["headers"] = kw.get("headers")
        return orig_get(url, **kw)

    monkeypatch.setattr(fake, "get", get)
    monkeypatch.setenv("CERTSPOTTER_API_KEY", "k123")
    asyncio.run(subdomains.enumerate_subdomains("x.com", []))
    assert seen["headers"] == {"Authorization": "Bearer k123"}
