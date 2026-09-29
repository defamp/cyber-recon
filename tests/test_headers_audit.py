import asyncio
from pathlib import Path

import pytest
from conftest import FakeResp

from recon.batch import TargetConfig
from recon.bundled_plugins.severity import severity_counter
from recon.cli import run_one
from recon.diff import diff_results
from recon.modules import http_probe
from recon.modules.headers_audit import audit_headers, audit_host
from recon.reporting.html_report import write_html_report
from recon.reporting.markdown import write_markdown_report

HARDENED = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def _host(headers=None, cookies=None, url="https://a.x.com/", status=200):
    return {
        "host": "a.x.com",
        "url": url,
        "status": status,
        "security_headers": headers or {},
        "set_cookies": cookies or [],
    }


def _checks(findings):
    return {f["check"] for f in findings}


def test_hardened_host_has_no_findings():
    assert audit_host(_host(HARDENED)) == []


def test_bare_https_host_reports_missing_headers():
    checks = _checks(audit_host(_host()))
    assert checks == {
        "hsts-missing",
        "csp-missing",
        "clickjacking",
        "nosniff-missing",
        "referrer-policy-missing",
    }


def test_hsts_not_expected_over_plain_http():
    checks = _checks(audit_host(_host(url="http://a.x.com/")))
    assert "hsts-missing" not in checks


def test_hsts_short_max_age():
    headers = {**HARDENED, "strict-transport-security": "max-age=300"}
    [f] = audit_host(_host(headers))
    assert (f["check"], f["severity"]) == ("hsts-short-max-age", "info")


def test_csp_unsafe_inline_flagged_unless_nonce():
    headers = {**HARDENED, "content-security-policy": "script-src 'self' 'unsafe-inline'"}
    checks = _checks(audit_host(_host(headers)))
    assert "csp-unsafe-inline" in checks
    assert "clickjacking" in checks  # no frame-ancestors and no XFO

    headers["content-security-policy"] = "script-src 'nonce-abc' 'unsafe-inline'"
    assert "csp-unsafe-inline" not in _checks(audit_host(_host(headers)))


def test_csp_script_src_falls_back_to_default_src():
    headers = {**HARDENED, "content-security-policy": "default-src *; frame-ancestors 'self'"}
    assert _checks(audit_host(_host(headers))) == {"csp-wildcard-script"}


def test_x_frame_options_satisfies_framing_check():
    headers = {**HARDENED, "content-security-policy": "default-src 'self'"}
    assert "clickjacking" in _checks(audit_host(_host(headers)))
    headers["x-frame-options"] = "SAMEORIGIN"
    assert "clickjacking" not in _checks(audit_host(_host(headers)))


def test_version_disclosure():
    headers = {**HARDENED, "server": "nginx/1.25.1", "x-powered-by": "Express"}
    [f] = audit_host(_host(headers))
    assert f["check"] == "version-disclosure"
    assert "nginx/1.25.1" in f["detail"]


def test_cookie_flags():
    cookies = [
        "sid=abc; Path=/; HttpOnly",
        "pref=dark; Secure; HttpOnly; SameSite=Lax",
    ]
    [f] = audit_host(_host(HARDENED, cookies))
    assert f["check"] == "cookie-flags"
    assert f["severity"] == "low"
    assert "'sid'" in f["detail"] and "Secure" in f["detail"] and "SameSite" in f["detail"]


def test_cookie_missing_secure_not_flagged_over_http():
    [f] = [
        f
        for f in audit_host(_host(cookies=["a=1; HttpOnly"], url="http://a.x.com/"))
        if f["check"] == "cookie-flags"
    ]
    assert f["severity"] == "info"
    assert "Secure" not in f["detail"]


def test_server_errors_are_skipped():
    assert audit_host(_host(status=502)) == []


def test_audit_headers_flattens_hosts():
    hosts = [_host(HARDENED), _host(), {"host": "b", "url": "", "status": 200}]
    assert len(audit_headers(hosts)) == 5


def test_probe_captures_audit_headers(fake_http, monkeypatch):
    monkeypatch.setattr(http_probe, "_resolve", lambda host: ["1.2.3.4"])
    resp = FakeResp(
        200,
        "<title>hi</title>",
        {
            "Strict-Transport-Security": "max-age=1",
            "Set-Cookie": "sid=1",
            "X-Unrelated": "ignored",
        },
    )
    resp.url = "https://a.x.com/"  # the probe reports the post-redirect URL
    fake_http({"https://a.x.com": resp})
    [host] = asyncio.run(http_probe.probe_targets(["a.x.com"]))
    assert host["security_headers"] == {"strict-transport-security": "max-age=1"}
    assert host["set_cookies"] == ["sid=1"]


def _results():
    return {
        "target": "x.com",
        "alive": [],
        "header_findings": audit_host(_host(cookies=["sid=1"])),
        "cors_reflective": {},
    }


def test_reports_include_header_findings(tmp_path: Path):
    write_markdown_report(_results(), tmp_path / "r.md")
    write_html_report(_results(), tmp_path / "r.html")
    md = (tmp_path / "r.md").read_text()
    html = (tmp_path / "r.html").read_text()
    assert "## Security headers (6)" in md
    assert "hsts-missing" in md and "hsts-missing" in html
    assert 'id="headers"' in html
    assert "Header issues" in html


def test_severity_counter_counts_header_findings():
    out = asyncio.run(severity_counter("x.com", _results()))
    sev = out["severity_summary"]
    assert sev["low"] == 4  # hsts, csp, clickjacking, cookie (missing Secure)
    assert sev["info"] == 2


def test_diff_tracks_header_findings_per_check():
    baseline = {"header_findings": audit_host(_host())}
    current = {"header_findings": audit_host(_host({"x-frame-options": "DENY"}))}
    delta = diff_results(baseline, current)
    assert [f["check"] for f in delta["removed"]["header_findings"]] == ["clickjacking"]
    assert delta["added"]["header_findings"] == []
    assert "-1 header_findings" in delta["summary"]


@pytest.mark.asyncio
async def test_run_one_audits_probed_hosts_and_honours_skip(tmp_path: Path, monkeypatch):
    async def fake_probe(hosts, **_):
        return [_host()]

    async def fake_subs(domain, errors, **_):
        return ["a.x.com"]

    monkeypatch.setattr("recon.cli.probe_targets", fake_probe)
    monkeypatch.setattr("recon.cli.enumerate_subdomains", fake_subs)
    cfg = TargetConfig(domain="x.com", output=str(tmp_path / "x"), skip=["wayback", "tls"])
    result = await run_one(cfg, no_html=True)
    assert "hsts-missing" in _checks(result["header_findings"])

    cfg = TargetConfig(
        domain="x.com", output=str(tmp_path / "y"), skip=["wayback", "headers", "tls"]
    )
    result = await run_one(cfg, no_html=True)
    assert result["header_findings"] == []


def test_redirect_only_gets_transport_and_cookie_checks():
    host = _host(cookies=["sid=1"], status=302)
    host["security_headers"] = {"server": "nginx/1.25.1"}
    checks = _checks(audit_host(host))
    assert checks == {"hsts-missing", "cookie-flags", "version-disclosure"}
