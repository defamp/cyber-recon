import json
from pathlib import Path

from recon.reporting.markdown import write_markdown_report
from recon.reporting.html_report import write_html_report


def _fake_results(target="example.com"):
    return {
        "target": target,
        "subdomains": ["a.example.com", "b.example.com"],
        "alive": [
            {
                "host": "a.example.com",
                "url": "https://a.example.com/",
                "status": 200,
                "server": "nginx",
                "title": "Welcome",
                "cors_acao": "*",
                "cors_acac": "",
                "technologies": ["nginx", "cloudflare"],
            },
            {
                "host": "b.example.com",
                "url": "https://b.example.com/",
                "status": 403,
                "server": "Apache",
                "title": "",
                "cors_acao": "",
                "cors_acac": "",
                "technologies": [],
            },
        ],
        "urls": ["https://example.com/a", "https://example.com/b.js"],
        "secrets": [
            {"url": "https://example.com/b.js", "pattern": "aws_access_key", "match": "AKIAIOSFODNN7EXAMPLE"},
        ],
        "cors_reflective": {},
    }


def test_markdown_report_creates_file(tmp_path: Path):
    out = tmp_path / "report.md"
    write_markdown_report(_fake_results(), out)
    assert out.exists()
    content = out.read_text()
    assert "example.com" in content
    assert "a.example.com" in content
    assert "https://example.com/b.js" in content
    assert "AKIAIOSFODNN7EXAMPLE" in content


def test_html_report_creates_file(tmp_path: Path):
    out = tmp_path / "report.html"
    write_html_report(_fake_results(), out)
    assert out.exists()
    content = out.read_text()
    assert "<!DOCTYPE html>" in content
    assert "example.com" in content
    assert "AKIAIOSFODNN7EXAMPLE" in content


def test_html_report_handles_empty_results(tmp_path: Path):
    out = tmp_path / "report.html"
    empty = {"target": "empty.test", "subdomains": [], "alive": [], "urls": [], "secrets": [], "cors_reflective": {}}
    write_html_report(empty, out)
    content = out.read_text()
    assert "empty.test" in content
    assert "No live hosts" in content or "No subdomains" in content


def test_markdown_report_handles_empty(tmp_path: Path):
    out = tmp_path / "report.md"
    empty = {"target": "empty.test", "subdomains": [], "alive": [], "urls": [], "secrets": []}
    write_markdown_report(empty, out)
    assert out.exists()
