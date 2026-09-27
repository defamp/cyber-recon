import asyncio

from recon.modules import advisories
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


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self._body


class _FakeSession:
    """Stand-in for aiohttp.ClientSession (respx only mocks httpx, not aiohttp)."""

    def __init__(self, status, body):
        self._resp = _FakeResp(status, body)
        self.urls: list[str] = []

    def __call__(self, *a, **kw):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kw):
        self.urls.append(url)
        return self._resp


def test_enrich_nuclei_attaches_advisory(monkeypatch):
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
    fake = _FakeSession(200, payload)
    monkeypatch.setattr(advisories.aiohttp, "ClientSession", fake)
    findings = [{"template-id": "CVE-2021-44228", "info": {"severity": "critical"}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert fake.urls == ["https://api.github.com/advisories?cve_id=CVE-2021-44228"]
    adv = out[0]["gh_advisory"][0]
    assert adv["cve"] == "CVE-2021-44228"
    assert adv["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert adv["severity"] == "critical"
    assert adv["cvss"] == 10.0


def test_enrich_nuclei_404_handled(monkeypatch):
    monkeypatch.setattr(advisories.aiohttp, "ClientSession", _FakeSession(404, None))
    findings = [{"template-id": "CVE-9999-99999", "info": {}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert out == findings  # unchanged when 404


def test_enrich_nuclei_non_200_records_error(monkeypatch):
    monkeypatch.setattr(advisories.aiohttp, "ClientSession", _FakeSession(403, None))
    findings = [{"template-id": "CVE-2021-44228", "info": {}}]
    out = asyncio.run(enrich_nuclei(findings))
    assert out[0]["gh_advisory"] == [{"cve": "CVE-2021-44228", "_error": "http 403"}]
