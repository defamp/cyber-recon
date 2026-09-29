from pathlib import Path

from recon.diff import diff_results
from recon.monitor import alert_items
from recon.priority import FINDING_CAP, score_hosts
from recon.reporting.html_report import write_html_report
from recon.reporting.markdown import write_markdown_report


def _alive(host, status=200, title="", scheme="https"):
    return {"host": host, "url": f"{scheme}://{host}/", "status": status, "title": title}


def _by_host(ranked):
    return {r["host"]: r for r in ranked}


def test_signals_add_up_with_reasons():
    results = {
        "alive": [_alive("app.x.com"), _alive("www.x.com")],
        "secrets": [
            {"url": "https://app.x.com/main.js", "pattern": "github_pat", "confidence": "high"},
            {"url": "https://app.x.com/main.js", "pattern": "jwt", "confidence": "low"},
        ],
        "nuclei": [
            {
                "template-id": "t1",
                "matched-at": "https://app.x.com/x",
                "info": {"severity": "high"},
            },
            {"_warning": "nuclei binary not found"},
        ],
        "cors_reflective": {"app.x.com": {"reflects": True, "acac": "true"}},
    }
    app = _by_host(score_hosts(results))["app.x.com"]
    assert app["score"] == 40 + 3 + 30 + 25 + 15
    assert app["reasons"][0] == "+40 high secret: github_pat"
    assert "+30 nuclei high: t1" in app["reasons"]
    assert _by_host(score_hosts(results))["www.x.com"]["score"] == 0


def test_findings_are_capped():
    results = {
        "alive": [_alive("a.x.com")],
        "header_findings": [{"host": "a.x.com", "severity": "low"}] * 10,
        "tls_findings": [{"host": "a.x.com", "severity": "medium"}],
    }
    [a] = score_hosts(results)
    assert a["score"] == FINDING_CAP
    assert a["reasons"] == [f"+{FINDING_CAP} header/TLS weaknesses"]


def test_keywords_match_whole_labels_only():
    results = {
        "alive": [
            _alive("jenkins-dev.x.com"),
            _alive("latest.x.com"),  # "test" inside a word must not count
            _alive("www.x.com", title="Admin Console"),
        ]
    }
    ranked = _by_host(score_hosts(results))
    assert ranked["jenkins-dev.x.com"]["reasons"] == ["+16 keywords: dev, jenkins"]
    assert ranked["latest.x.com"]["score"] == 0
    assert ranked["www.x.com"]["reasons"] == ["+16 keywords: admin, console"]


def test_status_and_new_host():
    results = {"alive": [_alive("a.x.com", 403), _alive("b.x.com", 502), _alive("c.x.com")]}
    ranked = score_hosts(results, new_hosts={"c.x.com"})
    assert [(r["host"], r["score"]) for r in ranked] == [
        ("c.x.com", 15),
        ("a.x.com", 5),
        ("b.x.com", 3),
    ]


def test_ranking_is_stable_for_ties():
    results = {"alive": [_alive("b.x.com"), _alive("a.x.com")]}
    assert [r["host"] for r in score_hosts(results)] == ["a.x.com", "b.x.com"]


def test_reports_show_top_priorities(tmp_path: Path):
    results = {
        "target": "x.com",
        "priority": [
            {"host": "a.x.com", "url": "https://a.x.com/", "score": 55, "reasons": ["+40 high secret: github_pat", "+15 new since last scan"]},
            {"host": "b.x.com", "url": "https://b.x.com/", "score": 0, "reasons": []},
        ],
    }  # fmt: skip
    write_markdown_report(results, tmp_path / "r.md")
    write_html_report(results, tmp_path / "r.html")
    md = (tmp_path / "r.md").read_text()
    assert "## Where to look first" in md
    assert "| 55 | https://a.x.com/ | +40 high secret: github_pat; +15 new since last scan |" in md
    assert "b.x.com/ |" not in md.split("## Subdomains")[0]  # zero scores are left out
    assert 'id="priority"' in (tmp_path / "r.html").read_text()


def test_reports_without_priority_have_no_section(tmp_path: Path):
    write_markdown_report({"target": "x.com"}, tmp_path / "r.md")
    write_html_report({"target": "x.com"}, tmp_path / "r.html")
    assert "Where to look first" not in (tmp_path / "r.md").read_text()
    assert 'id="priority"' not in (tmp_path / "r.html").read_text()


def test_tls_findings_are_diffed_and_alerted():
    f = {"host": "a.x.com", "check": "cert-expired", "severity": "medium", "detail": "d"}
    info = {"host": "a.x.com", "check": "cert-expiring-soon", "severity": "info", "detail": "d"}
    delta = diff_results({"tls_findings": []}, {"tls_findings": [f, info]})
    assert len(delta["added"]["tls_findings"]) == 2
    assert alert_items(delta) == {"TLS issues": ["a.x.com: cert-expired (medium)"]}


def test_keywords_ignore_the_target_domain_itself():
    results = {
        "target": "api-corp.test",
        "alive": [
            _alive("www.api-corp.test", title="Welcome to www.api-corp.test"),
            _alive("staging.api-corp.test"),
            _alive("api-corp.test"),
        ],
    }
    ranked = _by_host(score_hosts(results))
    assert ranked["www.api-corp.test"]["score"] == 0
    assert ranked["api-corp.test"]["score"] == 0
    assert ranked["staging.api-corp.test"]["reasons"] == ["+8 keywords: staging"]
