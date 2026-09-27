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
    fake_http({CRT: FakeResp(200, "<html>busy</html>"), HT: FakeResp(200, "no records found")})
    errors: list[str] = []
    assert asyncio.run(subdomains.enumerate_subdomains("x.com", errors)) == []
    assert errors == [
        "crt.sh: response was not JSON (crt.sh is likely overloaded) (after 3 attempts)"
    ]
