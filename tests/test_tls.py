"""TLS check tests against real local TLS servers (certificates made with openssl)."""

import asyncio
import shutil
import ssl
import subprocess  # nosec B404 — test-only, fixed arguments
from pathlib import Path

import pytest

from recon.batch import TargetConfig
from recon.cli import run_one
from recon.modules import tls
from recon.modules.tls import _classify_verify_error, check_host, check_tls

# Captured at import time, before the autouse network guard replaces it
REAL_HANDSHAKE = tls._handshake

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI needed")


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)  # nosec B603 B607


@pytest.fixture(scope="module")
def certs(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("certs")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
             "-out", "ca.pem", "-days", "30", "-subj", "/CN=Test CA", cwd=d)  # fmt: skip
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
             "-out", "leaf.csr", "-subj", "/CN=localhost", cwd=d)  # fmt: skip
    (d / "ext.cnf").write_text("subjectAltName=DNS:localhost\n")
    _openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
             "-CAcreateserial", "-out", "leaf.pem", "-days", "5", "-extfile", "ext.cnf",
             cwd=d)  # fmt: skip
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "self.key",
             "-out", "self.pem", "-days", "30", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost", cwd=d)  # fmt: skip
    return d


@pytest.fixture
def real_tls(monkeypatch, certs):
    """Allow real handshakes (to local servers only) and trust the test CA."""
    monkeypatch.setattr(tls, "_handshake", REAL_HANDSHAKE)
    monkeypatch.setattr(
        tls, "_verify_context", lambda: ssl.create_default_context(cafile=str(certs / "ca.pem"))
    )
    return certs


async def _check(certs: Path, name: str, host: str, *, legacy_server=False, legacy=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certs / f"{name}.pem", certs / f"{name}.key")
    if legacy_server:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

    async def handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        return await check_host({"host": host, "url": f"https://{host}:{port}/"}, legacy=legacy)
    finally:
        server.close()


def _checks(findings):
    return [f["check"] for f in findings]


def test_valid_cert_records_expiry(real_tls):
    info, findings = asyncio.run(_check(real_tls, "leaf", "localhost"))
    assert info["verified"] is True
    assert info["protocol"].startswith("TLS")
    assert info["issuer"] == "CN=Test CA"
    assert 3 <= info["days_left"] <= 5
    assert _checks(findings) == ["cert-expiring-soon"]
    assert "legacy_tls" not in info  # legacy check only when asked


def test_hostname_mismatch(real_tls):
    info, findings = asyncio.run(_check(real_tls, "leaf", "127.0.0.1"))
    assert info["verified"] is False
    assert _checks(findings) == ["cert-hostname-mismatch"]


def test_self_signed(real_tls):
    info, findings = asyncio.run(_check(real_tls, "self", "localhost"))
    assert _checks(findings) == ["cert-self-signed"]
    assert findings[0]["severity"] == "low"


def test_legacy_protocol_detection(real_tls):
    modern, _ = asyncio.run(_check(real_tls, "leaf", "localhost", legacy=True))
    legacy, findings = asyncio.run(
        _check(real_tls, "leaf", "localhost", legacy_server=True, legacy=True)
    )
    if legacy["legacy_tls"] == "untestable":
        pytest.skip("local OpenSSL refuses to offer TLS 1.0/1.1")
    assert modern["legacy_tls"] == "rejected"
    assert legacy["legacy_tls"] in ("TLSv1", "TLSv1.1")
    assert "legacy-tls" in _checks(findings)


def test_unreachable_host_is_an_error_not_a_finding(real_tls):
    info, findings = asyncio.run(
        check_host({"host": "localhost", "url": "https://localhost:1/"}, legacy=True)
    )
    assert info["verified"] is False and "error" in info
    assert findings == []
    assert "legacy_tls" not in info


def test_plain_http_is_skipped():
    assert asyncio.run(check_host({"host": "a", "url": "http://a.x.com/"})) == (None, [])


@pytest.mark.parametrize(
    ("message", "check"),
    [
        ("certificate has expired", "cert-expired"),
        ("self-signed certificate in certificate chain", "cert-self-signed"),
        ("Hostname mismatch, certificate is not valid for 'a.x.com'.", "cert-hostname-mismatch"),
        ("unable to get local issuer certificate", "cert-untrusted"),
    ],
)
def test_classify_verify_error(message, check):
    assert _classify_verify_error(message)[0] == check


def test_check_tls_aggregates(monkeypatch):
    async def fake_check(host, **kw):
        return {"host": host["host"], "legacy": kw["legacy"]}, [
            {"check": "x", "host": host["host"]}
        ]

    monkeypatch.setattr(tls, "check_host", fake_check)
    infos, findings = asyncio.run(check_tls([{"host": "a"}, {"host": "b"}], legacy=True))
    assert [i["host"] for i in infos] == ["a", "b"]
    assert len(findings) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(("active", "skip", "expected"), [(False, [], False), (True, [], True)])
async def test_run_one_runs_tls_legacy_only_when_active(
    tmp_path, monkeypatch, active, skip, expected
):
    seen = {}

    async def fake_probe(hosts, **_):
        return [{"host": "a.x.com", "url": "https://a.x.com/", "status": 200}]

    async def fake_subs(domain, errors, **_):
        return ["a.x.com"]

    async def fake_tls(hosts, *, legacy, limiter):
        seen["legacy"] = legacy
        return [{"host": "a.x.com"}], [
            {
                "host": "a.x.com",
                "url": "u",
                "check": "cert-self-signed",
                "severity": "low",
                "detail": "d",
            }
        ]

    async def no_cors(hosts, **_):
        return {}

    monkeypatch.setattr("recon.cli.enumerate_subdomains", fake_subs)
    monkeypatch.setattr("recon.cli.probe_targets", fake_probe)
    monkeypatch.setattr("recon.cli.check_tls", fake_tls)
    monkeypatch.setattr("recon.cli.check_cors_reflection", no_cors)
    cfg = TargetConfig(
        domain="x.com", output=str(tmp_path / "x"), skip=["wayback", *skip], active=active
    )
    result = await run_one(cfg, no_html=False)
    assert seen["legacy"] is expected
    assert result["tls_findings"][0]["check"] == "cert-self-signed"
    assert result["severity_summary"]["low"] >= 1
    assert "cert-self-signed" in (tmp_path / "x" / "report.md").read_text()
    assert 'id="tls"' in (tmp_path / "x" / "report.html").read_text()


@pytest.mark.asyncio
async def test_run_one_skip_tls(tmp_path, monkeypatch):
    async def fake_probe(hosts, **_):
        return [{"host": "a.x.com", "url": "https://a.x.com/", "status": 200}]

    async def fake_subs(domain, errors, **_):
        return ["a.x.com"]

    monkeypatch.setattr("recon.cli.enumerate_subdomains", fake_subs)
    monkeypatch.setattr("recon.cli.probe_targets", fake_probe)
    cfg = TargetConfig(domain="x.com", output=str(tmp_path / "x"), skip=["wayback", "tls"])
    result = await run_one(cfg, no_html=True)
    assert result["tls"] == [] and result["tls_findings"] == []
