import asyncio

from conftest import FakeResp

from recon.modules.wayback import fetch_wayback_urls

WB = "https://web.archive.org/"


def test_limit_is_sent_and_truncation_reported(fake_http):
    rows = [["original"]] + [[f"https://x.com/{i}"] for i in range(3)]
    fake = fake_http({WB: FakeResp(200, rows)})
    errors: list[str] = []
    urls = asyncio.run(fetch_wayback_urls("x.com", errors, limit=3))
    assert "limit=3" in fake.urls[0]
    assert len(urls) == 3
    assert errors == ["wayback: result truncated at 3 URLs (raise it with --wayback-limit)"]


def test_no_warning_below_limit(fake_http):
    fake_http({WB: FakeResp(200, [["original"], ["https://x.com/a"]])})
    errors: list[str] = []
    assert asyncio.run(fetch_wayback_urls("x.com", errors, limit=10)) == ["https://x.com/a"]
    assert errors == []
