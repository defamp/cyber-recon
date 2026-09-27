"""Integration tests — end-to-end CLI with mocked network responses."""

from pathlib import Path

import pytest

from recon.batch import TargetConfig
from recon.cli import run_one


def _cfg(target="example.com", output=None, **kw) -> TargetConfig:
    return TargetConfig(
        domain=target,
        output=output or f"output/{target}",
        active=kw.get("active", False),
        nuclei=kw.get("nuclei", False),
        skip=kw.get("skip", []),
    )


@pytest.mark.asyncio
async def test_run_one_passive_no_network_hits(tmp_path: Path, respx_mock):
    """Pure passive run with no live hosts — should complete quickly."""
    respx_mock.get("https://crt.sh/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").respond(200, content="")
    respx_mock.get("https://web.archive.org/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )

    cfg = _cfg(target="example.com", output=str(tmp_path / "ex"))
    cfg.skip = ["subdomains", "wayback", "secrets", "http"]  # all skipped
    result = await run_one(cfg, no_html=True)
    assert result["target"] == "example.com"
    assert (tmp_path / "ex" / "results.json").exists()
    assert (tmp_path / "ex" / "report.md").exists()


@pytest.mark.asyncio
async def test_run_one_writes_html(tmp_path: Path, respx_mock):
    respx_mock.get("https://crt.sh/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").respond(200, content="")
    respx_mock.get("https://web.archive.org/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    await run_one(cfg, no_html=False)
    assert (tmp_path / "x" / "report.html").exists()


@pytest.mark.asyncio
async def test_run_one_html_has_search_box(tmp_path: Path, respx_mock):
    respx_mock.get("https://crt.sh/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").respond(200, content="")
    respx_mock.get("https://web.archive.org/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    await run_one(cfg, no_html=False)
    html = (tmp_path / "x" / "report.html").read_text()
    assert "globalSearch" in html


@pytest.mark.asyncio
async def test_run_one_severity_counter_runs_by_default(tmp_path: Path, respx_mock):
    """Bundled plugin severity_counter should run and populate severity_summary."""
    respx_mock.get("https://crt.sh/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").respond(200, content="")
    respx_mock.get("https://web.archive.org/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    cfg = _cfg(
        target="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains", "wayback", "secrets", "http"],
    )
    result = await run_one(cfg, no_html=True)
    assert "severity_summary" in result


@pytest.mark.asyncio
async def test_run_one_skip_plugins(tmp_path: Path, respx_mock):
    respx_mock.get("https://crt.sh/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").respond(200, content="")
    respx_mock.get("https://web.archive.org/").respond(
        200, content="[]", headers={"Content-Type": "application/json"}
    )
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
