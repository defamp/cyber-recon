import asyncio
import json
import time
from pathlib import Path

import pytest
from conftest import FakeResp, FakeSession

from recon.batch import TargetConfig
from recon.cli import run, run_batch, run_one
from recon.ratelimit import RateLimiter, scoped_get
from recon.scope import Scope, load_scope, normalize_host


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        ("API.Example.com", "api.example.com"),
        ("https://app.example.com/path?q=1", "app.example.com"),
        ("app.example.com:8443", "app.example.com"),
        ("app.example.com.", "app.example.com"),
        ("app.example.com/login", "app.example.com"),
    ],
)
def test_normalize_host(raw, host):
    assert normalize_host(raw) == host


def test_rule_kinds_and_exclude_wins():
    scope = Scope.from_entries(
        ["*.example.com", "example.com", r"re:^api\d+\.example\.org$"],
        ["legacy.example.com", "*.internal.example.com"],
    )
    assert scope.in_scope("example.com")
    assert scope.in_scope("a.b.example.com")
    assert scope.in_scope("API7.example.org")
    assert not scope.in_scope("api.example.org")  # regex is a full match
    assert not scope.in_scope("legacy.example.com")
    assert not scope.in_scope("x.internal.example.com")
    assert not scope.in_scope("notexample.com")
    assert not scope.in_scope("")


def test_wildcard_does_not_cover_apex():
    scope = Scope.from_entries(["*.example.com"])
    assert not scope.in_scope("example.com")


def test_url_in_scope():
    scope = Scope.default_for("example.com")
    assert scope.url_in_scope("https://a.example.com:8443/x.js")
    assert not scope.url_in_scope("https://cdn.other.net/x.js")
    assert not scope.url_in_scope("not a url")


def test_invalid_entries_rejected():
    with pytest.raises(ValueError, match="regex"):
        Scope.from_entries(["re:(unclosed"])
    with pytest.raises(ValueError, match="unsupported"):
        Scope.from_entries(["api.*.example.com"])
    with pytest.raises(ValueError, match="at least one include"):
        Scope.from_entries([])


def test_load_yaml_scope(tmp_path: Path):
    path = tmp_path / "scope.yml"
    path.write_text(
        "include:\n  - '*.example.com'\n  - example.com\nexclude:\n  - old.example.com\n"
        "rate_limit: 5\n"
    )
    scope = load_scope(path)
    assert scope.rate_limit == 5.0
    assert scope.in_scope("a.example.com")
    assert not scope.in_scope("old.example.com")
    assert scope.summary()["source"] == str(path)


def test_load_plain_text_scope(tmp_path: Path):
    path = tmp_path / "scope.txt"
    path.write_text("# program scope\n*.example.com\nshop.example.net  # extra\n!old.example.com\n")
    scope = load_scope(path)
    assert scope.in_scope("a.example.com")
    assert scope.in_scope("shop.example.net")
    assert not scope.in_scope("old.example.com")
    assert scope.rate_limit is None


def test_exact_hosts_skips_excluded():
    scope = Scope.from_entries(["a.example.com", "b.example.com", "*.x.com"], ["b.example.com"])
    assert scope.exact_hosts() == ["a.example.com"]


def test_rate_limiter_spaces_requests():
    async def burst(limiter, n):
        start = time.monotonic()
        await asyncio.gather(*(limiter.wait() for _ in range(n)))
        return time.monotonic() - start

    assert asyncio.run(burst(RateLimiter(50), 6)) >= 0.09  # 5 gaps of 20ms
    assert asyncio.run(burst(RateLimiter(None), 50)) < 0.05
    assert RateLimiter(0).rate is None


def _redirect(location):
    return FakeResp(302, "", {"Location": location})


def _get(routes, url, scope=None, **kw):
    async def go():
        session = FakeSession(routes)
        async with scoped_get(session, url, scope=scope, **kw) as (r, final):
            return r.status, final, session.urls

    return asyncio.run(go())


def test_scoped_get_follows_in_scope_redirects():
    routes = {
        "https://a.x.com/login": FakeResp(200, "ok"),
        "https://a.x.com/": _redirect("/login"),
    }
    status, final, urls = _get(routes, "https://a.x.com/", Scope.default_for("x.com"))
    assert (status, final) == (200, "https://a.x.com/login")
    assert urls == ["https://a.x.com/", "https://a.x.com/login"]


def test_scoped_get_stops_at_out_of_scope_redirect():
    routes = {"https://a.x.com/": _redirect("https://sso.vendor.net/auth")}
    status, final, urls = _get(routes, "https://a.x.com/", Scope.default_for("x.com"))
    assert (status, final) == (302, "https://a.x.com/")
    assert urls == ["https://a.x.com/"]  # sso.vendor.net never contacted


def test_scoped_get_without_scope_follows_anywhere():
    routes = {
        "https://sso.vendor.net/": FakeResp(200, "ok"),
        "https://a.x.com/": _redirect("https://sso.vendor.net/"),
    }
    status, final, _ = _get(routes, "https://a.x.com/")
    assert (status, final) == (200, "https://sso.vendor.net/")


def test_scoped_get_redirect_loop():
    with pytest.raises(RuntimeError, match="too many redirects"):
        _get({"https://a.x.com/": _redirect("https://a.x.com/")}, "https://a.x.com/")


def test_nuclei_gets_rate_limit(tmp_path, monkeypatch):
    from recon.modules import nuclei

    args_file = tmp_path / "args"
    bin_path = tmp_path / "nuclei"
    bin_path.write_text(f'#!/bin/sh\necho "$@" > {args_file}\n')
    bin_path.chmod(0o755)
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", str(bin_path))
    asyncio.run(nuclei.run_nuclei([{"url": "https://x.com/"}], timeout=10, rate_limit=2.7))
    assert "-rl 2" in args_file.read_text()


def _scope_file(tmp_path: Path, text: str) -> str:
    path = tmp_path / "scope.txt"
    path.write_text(text)
    return str(path)


@pytest.mark.asyncio
async def test_run_one_applies_scope(tmp_path: Path, monkeypatch):
    probed: dict = {}

    async def fake_subs(domain, errors):
        return ["a.x.com", "old.x.com"]

    async def fake_wayback(domain, errors):
        return ["https://a.x.com/app.js", "https://old.x.com/app.js"]

    async def fake_probe(hosts, *, scope, limiter):
        probed.update(hosts=list(hosts), scope=scope, rate=limiter.rate)
        return []

    monkeypatch.setattr("recon.cli.enumerate_subdomains", fake_subs)
    monkeypatch.setattr("recon.cli.fetch_wayback_urls", fake_wayback)
    monkeypatch.setattr("recon.cli.probe_targets", fake_probe)
    scope = _scope_file(tmp_path, "*.x.com\nextra.x.com\nother.org\n!old.x.com\n")
    cfg = TargetConfig(
        domain="X.com", output=str(tmp_path / "o"), skip=["secrets"], scope=scope, rate=3
    )
    result = await run_one(cfg, no_html=True)

    # other.org is in the program scope but not part of this target
    assert probed["hosts"] == ["a.x.com", "extra.x.com"]
    assert probed["rate"] == 3
    assert result["subdomains"] == ["a.x.com", "extra.x.com"]
    assert result["out_of_scope"] == {"subdomains": ["old.x.com"], "urls": 1}
    assert result["urls"] == ["https://a.x.com/app.js"]
    assert result["scope"]["exclude"] == ["old.x.com"]
    assert result["scope"]["rate_limit"] == 3


@pytest.mark.asyncio
async def test_default_scope_changes_nothing(tmp_path: Path, monkeypatch):
    async def fake_wayback(domain, errors):
        return ["https://x.com/a.js", "https://a.x.com/b.js"]

    monkeypatch.setattr("recon.cli.fetch_wayback_urls", fake_wayback)
    cfg = TargetConfig(domain="x.com", output=str(tmp_path / "o"), skip=["subdomains", "secrets"])
    result = await run_one(cfg, no_html=True)
    assert result["urls"] == ["https://x.com/a.js", "https://a.x.com/b.js"]
    assert result["out_of_scope"] == {"subdomains": [], "urls": 0}
    assert result["scope"]["source"] == "default"
    assert result["scope"]["rate_limit"] is None


@pytest.mark.asyncio
async def test_cli_rejects_bad_scope_before_scanning(tmp_path: Path, fake_http):
    from test_integration import _args

    fake = fake_http({})
    scope = _scope_file(tmp_path, "re:(broken\n")
    assert await run(_args(tmp_path, scope=scope)) == 2
    assert fake.urls == []
    assert not (tmp_path / "x" / "results.json").exists()


@pytest.mark.asyncio
async def test_batch_cli_scope_is_fallback_and_rate_overrides(tmp_path: Path, monkeypatch):
    seen = []

    async def fake_run_one(cfg, **_):
        seen.append((cfg.domain, cfg.scope, cfg.rate))
        return {}

    monkeypatch.setattr("recon.cli.run_one", fake_run_one)
    batch = tmp_path / "batch.yml"
    batch.write_text(
        json.dumps(
            {
                "targets": [
                    {"domain": "a.com", "scope": "own.txt", "rate": 9},
                    {"domain": "b.com"},
                ]
            }
        )
    )
    code = await run_batch(
        batch,
        no_html=True,
        active=False,
        nuclei=False,
        nuclei_templates=None,
        webhook=None,
        enrich_cve=False,
        plugin_names=[],
        run_default_plugins=False,
        scope="cli.txt",
        rate=2,
    )
    assert code == 0
    assert seen == [("a.com", "own.txt", 2), ("b.com", "cli.txt", 2)]


def test_batch_config_reads_scope_and_rate():
    cfg = TargetConfig.from_dict({"domain": "a.com", "scope": "s.yml", "rate": 4})
    assert (cfg.scope, cfg.rate) == ("s.yml", 4)


def test_example_scope_file_parses():
    scope = load_scope(Path(__file__).parent.parent / "scope.example.txt")
    assert scope.in_scope("example.com") and scope.in_scope("app.example.com")
    assert not scope.in_scope("legacy.example.com")
    assert not scope.in_scope("vpn.corp.example.com")


def test_reports_show_scope(tmp_path: Path):
    from recon.reporting.html_report import write_html_report
    from recon.reporting.markdown import write_markdown_report

    results = {
        "target": "x.com",
        "scope": {"source": "scope.txt", "rate_limit": 5.0},
        "out_of_scope": {"subdomains": ["old.x.com"], "urls": 3},
    }
    write_markdown_report(results, tmp_path / "r.md")
    write_html_report(results, tmp_path / "r.html")
    line = "Scope: scope.txt · 1 out-of-scope subdomain(s) not probed · 3 out-of-scope URL(s) dropped · rate limit 5 req/s"
    assert line in (tmp_path / "r.md").read_text()
    assert line in (tmp_path / "r.html").read_text()
