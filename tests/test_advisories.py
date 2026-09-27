import asyncio

from recon.modules.advisories import _extract_cves, enrich_nuclei


def test_extract_cves_from_template_id():
    f = {"template-id": "CVE-2021-44228", "info": {}}
    assert _extract_cves(f) == ["CVE-2021-44228"]


def test_extract_cves_from_tags():
    f = {"template-id": "log4shell", "info": {"tags": ["CVE-2021-44228", "rce"]}}
    assert "CVE-2021-44228" in _extract_cves(f)


def test_extract_cves_from_classification():
    f = {"template-id": "x", "info": {"classification": {"cve-id": "CVE-2024-1234"}}}
    assert "CVE-2024-1234" in _extract_cves(f)


def test_extract_cves_dedupes():
    f = {
        "template-id": "CVE-2021-44228",
        "info": {"tags": ["CVE-2021-44228"], "classification": {"cve": "CVE-2021-44228"}},
    }
    assert _extract_cves(f) == ["CVE-2021-44228"]


def test_extract_cves_caps_at_three():
    f = {
        "template-id": "CVE-2021-44228",
        "info": {"tags": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-4104"]},
    }
    assert len(_extract_cves(f)) == 3


def test_extract_cves_none_when_absent():
    f = {"template-id": "log4shell", "info": {"tags": ["rce"]}}
    assert _extract_cves(f) == []


def test_enrich_nuclei_no_cve_passthrough():
    findings = [{"template-id": "no-cve-here", "info": {"severity": "info"}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert out == findings  # unchanged


def test_enrich_nuclei_attaches_advisory(respx_mock):
    payload = [
        {
            "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
            "summary": "Log4Shell RCE",
            "severity": "critical",
            "cvss": {"score": 10.0},
            "published_at": "2021-12-10T00:00:00Z",
            "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
        }
    ]
    respx_mock.get("https://api.github.com/advisories").respond(
        200,
        json=payload,
    )
    findings = [{"template-id": "CVE-2021-44228", "info": {"severity": "critical"}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert "gh_advisory" in out[0]
    assert out[0]["gh_advisory"][0]["cve"] == "CVE-2021-44228"
    assert out[0]["gh_advisory"][0]["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"


def test_enrich_nuclei_404_handled(respx_mock):
    respx_mock.get("https://api.github.com/advisories").respond(404)
    findings = [{"template-id": "CVE-9999-99999", "info": {}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert out == findings  # unchanged when 404


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def headers(self):
        return {"Content-Type": "application/json"}

    async def json(self, content_type=None):
        return self._body
