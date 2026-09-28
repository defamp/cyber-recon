"""Integration tests — end-to-end CLI with mocked network responses."""

import argparse
import json
from pathlib import Path

import aiohttp
import pytest
from conftest import FakeResp

from recon.batch import TargetConfig
from recon.cli import run, run_one


def _cfg(target="example.com", output=None, **kw) -> TargetConfig:
    return TargetConfig(
        domain=target,
        output=output or f"output/{target}",
        active=kw.get("active", False),
        nuclei=kw.get("nuclei", False),
        skip=kw.get("skip", []),
    )


@pytest.mark.asyncio
async def test_run_one_passive_no_network_hits(tmp_path: Path):
    """Pure passive run with no live hosts — should complete quickly."""
    cfg = _cfg(target="example.com", output=str(tmp_path / "ex"))
    cfg.skip = ["subdomains", "wayback", "secrets", "http"]  # all skipped
    result = await run_one(cfg, no_html=True)
    assert result["target"] == "example.com"
    assert (tmp_path / "ex" / "results.json").exists()
    assert (tmp_path / "ex" / "report.md").exists()


@pytest.mark.asyncio
async def test_run_one_writes_html(tmp_path: Path):
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    await run_one(cfg, no_html=False)
    assert (tmp_path / "x" / "report.html").exists()


@pytest.mark.asyncio
async def test_run_one_html_has_search_box(tmp_path: Path):
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    await run_one(cfg, no_html=False)
    html = (tmp_path / "x" / "report.html").read_text()
    assert "globalSearch" in html


@pytest.mark.asyncio
async def test_run_one_severity_counter_runs_by_default(tmp_path: Path):
    """Bundled plugin severity_counter should run and populate severity_summary."""
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    result = await run_one(cfg, no_html=True)
    assert "severity_summary" in result


@pytest.mark.asyncio
async def test_run_one_skip_plugins(tmp_path: Path):
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    result = await run_one(cfg, no_html=True, run_default_plugins=False)
    assert "severity_summary" not in result


@pytest.mark.asyncio
async def test_run_one_handles_failure_gracefully(tmp_path: Path):
    """If everything fails (no mocks), we still get a results.json written."""
    cfg = _cfg(
        target="offline.invalid",
        output=str(tmp_path / "off"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    result = await run_one(cfg, no_html=True)
    assert (tmp_path / "off" / "results.json").exists()
    assert result["target"] == "offline.invalid"


def test_cli_help_mentions_new_flags(capsys):
    """Run --help and verify new flags appear."""
    import sys

    from recon.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["recon", "--help"]
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv
    captured = capsys.readouterr()
    text = (captured.out or "") + (captured.err or "")
    for flag in ("--diff", "--plugin", "--list-plugins", "--enrich-cve", "--nuclei-live"):
        assert flag in text, f"missing {flag} in help"


CRT = "https://crt.sh/"
HT = "https://api.hackertarget.com/"
WB = "https://web.archive.org/"


@pytest.mark.asyncio
async def test_run_one_records_source_errors(tmp_path: Path, fake_http):
    fake_http(
        {
            CRT: FakeResp(502),
            HT: FakeResp(200, "API count exceeded - Increase Quota with Membership"),
            WB: aiohttp.ClientConnectionError("connection refused"),
        }
    )
    cfg = _cfg(target="x.com", output=str(tmp_path / "x"), skip=["http", "secrets"])
    result = await run_one(cfg, no_html=False)
    assert result["errors"] == [
        "crt.sh: http 502",
        "hackertarget: API count exceeded - Increase Quota with Membership",
        "wayback: ClientConnectionError: connection refused",
    ]
    saved = json.loads((tmp_path / "x" / "results.json").read_text())
    assert saved["errors"] == result["errors"]
    assert "crt.sh: http 502" in (tmp_path / "x" / "report.md").read_text()
    assert "source error(s)" in (tmp_path / "x" / "report.html").read_text()


@pytest.mark.asyncio
async def test_run_one_no_errors_on_success(tmp_path: Path, fake_http):
    fake_http(
        {
            CRT: FakeResp(200, [{"name_value": "a.x.com\nb.x.com"}]),
            HT: FakeResp(200, "c.x.com,1.2.3.4\n"),
            WB: FakeResp(200, [["original"], ["https://x.com/app.js"]]),
        }
    )
    cfg = _cfg(target="x.com", output=str(tmp_path / "x"), skip=["http", "secrets"])
    result = await run_one(cfg, no_html=True)
    assert result["errors"] == []
    assert result["subdomains"] == ["a.x.com", "b.x.com", "c.x.com"]
    assert result["urls"] == ["https://x.com/app.js"]
    assert result["timestamp"]


def _args(tmp_path: Path, **kw) -> argparse.Namespace:
    base = dict(
        list_plugins=False,
        batch=None,
        target="x.com",
        output=str(tmp_path / "x"),
        active=False,
        nuclei=False,
        nuclei_templates=None,
        nuclei_tags=None,
        nuclei_live=False,
        enrich_cve=False,
        diff=None,
        plugin=[],
        webhook=None,
        no_subdomains=True,
        no_wayback=True,
        no_secrets=True,
        no_headers=True,
        no_html=True,
        no_plugins=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_cli_no_flags_skip_modules(tmp_path: Path, fake_http):
    fake = fake_http({})  # any request would raise "unexpected request"
    assert await run(_args(tmp_path)) == 0
    assert fake.urls == []


@pytest.mark.asyncio
async def test_cli_diff_against_baseline_in_same_output_dir(tmp_path: Path, fake_http):
    """Documented usage: --diff <output>/results.json. The scan must not
    overwrite the baseline before it is read."""
    fake_http({})
    out = tmp_path / "x"
    out.mkdir()
    baseline = {"target": "x.com", "subdomains": ["old.x.com"], "alive": [], "urls": []}
    (out / "results.json").write_text(json.dumps(baseline))
    assert await run(_args(tmp_path, diff=str(out / "results.json"))) == 0
    delta = json.loads((out / "diff.json").read_text())
    assert delta["removed"]["subdomains"] == ["old.x.com"]


@pytest.mark.asyncio
async def test_cli_diff_missing_baseline_fails_before_scan(tmp_path: Path, fake_http):
    fake_http({})
    assert await run(_args(tmp_path, diff=str(tmp_path / "nope.json"))) == 3
    assert not (tmp_path / "x" / "results.json").exists()


@pytest.mark.asyncio
async def test_named_plugin_runs_in_addition_to_defaults(tmp_path: Path):
    from recon.plugins import register, unregister

    async def extra(target, results, **_):
        return {"extra_ran": True}

    register("extra_test_plugin", extra)
    try:
        cfg = _cfg(target="x.com", output=str(tmp_path / "x"), skip=["subdomains", "wayback"])
        result = await run_one(cfg, no_html=True, plugin_names=["extra_test_plugin"])
    finally:
        unregister("extra_test_plugin")
    assert result["extra_ran"] is True
    assert "severity_summary" in result  # default plugin still ran
    assert result["errors"] == []


@pytest.mark.asyncio
async def test_unknown_plugin_is_reported(tmp_path: Path):
    cfg = _cfg(target="x.com", output=str(tmp_path / "x"), skip=["subdomains", "wayback"])
    result = await run_one(cfg, no_html=True, plugin_names=["does_not_exist"])
    assert result["errors"] == ["plugin: unknown plugin 'does_not_exist' (see --list-plugins)"]


@pytest.mark.asyncio
async def test_html_header_reflects_scan_mode(tmp_path: Path):
    skip = ["subdomains", "wayback"]
    await run_one(_cfg(target="x.com", output=str(tmp_path / "p"), skip=skip), no_html=False)
    cfg = _cfg(target="x.com", output=str(tmp_path / "a"), skip=skip, active=True)
    await run_one(cfg, no_html=False)
    assert "passive only" in (tmp_path / "p" / "report.html").read_text()
    assert "active modules enabled" in (tmp_path / "a" / "report.html").read_text()
