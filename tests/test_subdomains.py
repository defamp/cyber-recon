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


# --- passive sources (responses mocked; real API formats need live verification)

import asyncio  # noqa: E402

import pytest  # noqa: E402
from conftest import FakeResp  # noqa: E402

from recon.modules.subdomains import (  # noqa: E402
    SOURCES,
    enumerate_subdomains,
    hosts_from_urls,
)

CRT = "https://crt.sh/"
HT = "https://api.hackertarget.com/"
CS = "https://api.certspotter.com/"
OTX = "https://otx.alienvault.com/"
US = "https://urlscan.io/"


def _run(fake_http, routes, sources, **env):
    session = fake_http(routes)
    errors: list[str] = []
    stats: dict[str, int] = {}
    hosts = asyncio.run(enumerate_subdomains("x.com", errors, sources=sources, stats=stats))
    return hosts, errors, stats, session


def test_certspotter_parses_dns_names(fake_http):
    body = [
        {"id": "1", "dns_names": ["a.x.com", "*.b.x.com", "x.com"]},
        {"id": "2", "dns_names": ["c.x.com", "other.org"]},
        "garbage",
    ]
    hosts, errors, stats, _ = _run(fake_http, {CS: FakeResp(200, body)}, ["certspotter"])
    assert hosts == ["a.x.com", "b.x.com", "c.x.com"]
    assert errors == []
    assert stats == {"certspotter": 3}


def test_otx_parses_passive_dns(fake_http):
    body = {"passive_dns": [{"hostname": "a.x.com"}, {"hostname": "evil.net"}, {"x": 1}]}
    hosts, errors, _, _ = _run(fake_http, {OTX: FakeResp(200, body)}, ["otx"])
    assert hosts == ["a.x.com"]
    assert errors == []


def test_urlscan_parses_page_and_task_domains(fake_http):
    body = {
        "results": [
            {"page": {"domain": "a.x.com"}, "task": {"domain": "b.x.com"}},
            {"page": {}, "task": {"domain": "cdn.other.net"}},
        ]
    }
    hosts, errors, _, _ = _run(fake_http, {US: FakeResp(200, body)}, ["urlscan"])
    assert hosts == ["a.x.com", "b.x.com"]
    assert errors == []


@pytest.mark.parametrize(
    ("source", "prefix", "body"),
    [("certspotter", CS, {"error": "x"}), ("otx", OTX, []), ("urlscan", US, {"total": 0})],
)
def test_unexpected_format_is_reported(fake_http, source, prefix, body):
    hosts, errors, _, _ = _run(fake_http, {prefix: FakeResp(200, body)}, [source])
    assert hosts == []
    assert errors == [f"{source}: unexpected response format"]


def test_rate_limit_hint(fake_http):
    _, errors, stats, _ = _run(fake_http, {US: FakeResp(429)}, ["urlscan"])
    assert errors == ["urlscan: http 429 (rate limited — set an API key?)"]
    assert stats == {"urlscan": 0}


def test_api_keys_sent_only_when_set(fake_http, monkeypatch):
    routes = {CS: FakeResp(200, []), OTX: FakeResp(200, {"passive_dns": []})}
    _, _, _, session = _run(fake_http, routes, ["certspotter", "otx"])
    assert [kw["headers"] for kw in session.kwargs] == [{}, {}]

    monkeypatch.setenv("CERTSPOTTER_API_KEY", "cs-key")
    monkeypatch.setenv("OTX_API_KEY", "otx-key")
    routes = {CS: FakeResp(200, []), OTX: FakeResp(200, {"passive_dns": []})}
    _, _, _, session = _run(fake_http, routes, ["certspotter", "otx"])
    assert [kw["headers"] for kw in session.kwargs] == [
        {"Authorization": "Bearer cs-key"},
        {"X-OTX-API-KEY": "otx-key"},
    ]


def test_all_sources_merged_and_one_failure_does_not_stop_others(fake_http):
    routes = {
        CRT: FakeResp(200, [{"name_value": "a.x.com\nb.x.com"}]),
        HT: FakeResp(200, "b.x.com,1.2.3.4\n"),
        CS: FakeResp(502),
        OTX: FakeResp(200, {"passive_dns": [{"hostname": "c.x.com"}]}),
        US: FakeResp(200, {"results": [{"page": {"domain": "d.x.com"}}]}),
    }
    hosts, errors, stats, _ = _run(fake_http, routes, None)
    assert hosts == ["a.x.com", "b.x.com", "c.x.com", "d.x.com"]
    assert errors == ["certspotter: http 502"]
    assert stats == {"crtsh": 2, "hackertarget": 1, "certspotter": 0, "otx": 1, "urlscan": 1}
    assert set(stats) == set(SOURCES)


def test_unknown_source_rejected():
    with pytest.raises(ValueError, match="unknown subdomain source"):
        asyncio.run(enumerate_subdomains("x.com", sources=["nope"]))


def test_hosts_from_urls():
    urls = [
        "https://a.x.com/app.js",
        "http://B.x.com:8080/x",
        "https://x.com/",
        "https://other.org/x",
        "http://[::1/broken",
    ]
    assert hosts_from_urls("x.com", urls) == ["a.x.com", "b.x.com"]
