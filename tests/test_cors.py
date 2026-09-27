import asyncio

from conftest import FakeResp

from recon.modules import cors
from recon.modules.cors import check_cors_reflection
from recon.reporting.html_report import _cors_issues


def _host():
    return [{"host": "a.x.com", "url": "https://a.x.com/"}]


def test_reflected_origin_detected(fake_http, monkeypatch):
    monkeypatch.setattr(cors, "_rand_origin", lambda: "https://probe-abc.example")
    fake_http(
        {
            "https://a.x.com/": FakeResp(
                200,
                "",
                {
                    "Access-Control-Allow-Origin": "https://probe-abc.example",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        }
    )
    out = asyncio.run(check_cors_reflection(_host()))
    assert out["a.x.com"]["reflects"] is True
    assert out["a.x.com"]["acac"] == "true"


def test_wildcard_is_not_reflection(fake_http):
    fake_http({"https://a.x.com/": FakeResp(200, "", {"Access-Control-Allow-Origin": "*"})})
    out = asyncio.run(check_cors_reflection(_host()))
    assert out["a.x.com"]["reflects"] is False
    assert out["a.x.com"]["acao"] == "*"


def test_html_reports_reflection_missing_from_passive_probe():
    """Passive probe sends no Origin, so ACAO is empty there; the active
    probe's reflection must still be reported."""
    hosts = [{"host": "a.x.com", "url": "https://a.x.com/", "cors_acao": "", "cors_acac": ""}]
    reflective = {
        "a.x.com": {
            "reflects": True,
            "acao": "https://probe-abc.example",
            "acac": "true",
            "tested_origin": "https://probe-abc.example",
        }
    }
    issues = _cors_issues(hosts, reflective)
    assert len(issues) == 1
    assert issues[0][0] == "critical"
    assert issues[0][3] == "https://probe-abc.example"
