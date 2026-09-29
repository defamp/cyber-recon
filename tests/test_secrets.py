from recon.modules.secrets import PATTERNS, _filter_js_urls


def test_filter_js_urls_basic():
    urls = [
        "https://x.com/a.js",
        "https://x.com/a.css",
        "https://x.com/b.mjs",
        "https://x.com/page.html",
    ]
    result = _filter_js_urls(urls)
    assert "https://x.com/a.js" in result
    assert "https://x.com/b.mjs" in result
    assert "https://x.com/a.css" not in result
    assert "https://x.com/page.html" not in result


def test_filter_js_urls_respects_limit():
    urls = [f"https://x.com/{i}.js" for i in range(300)]
    result = _filter_js_urls(urls)
    assert len(result) <= 200


def test_pattern_aws_access_key():
    pat = PATTERNS["aws_access_key"]
    import re

    text = "AKIAIOSFODNN7EXAMPLE aws_key=AKIA1234567890ABCDEF"
    matches = re.findall(pat, text)
    assert "AKIAIOSFODNN7EXAMPLE" in matches
    assert "AKIA1234567890ABCDEF" in matches


def test_pattern_github_pat():
    import re

    pat = PATTERNS["github_pat"]
    assert re.search(pat, "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB")


def test_pattern_slack_token():
    import re

    pat = PATTERNS["slack_token"]
    assert re.search(pat, "xoxb-1234567890-abcdefghij")


def test_pattern_jwt():
    import re

    pat = PATTERNS["jwt"]
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert re.search(pat, jwt)


def test_pattern_google_api():
    import re

    pat = PATTERNS["google_api"]
    assert re.search(pat, "AIzaSyA-1234567890abcdefghijklmnopqrstuvw")


def test_pattern_private_key():
    import re

    pat = PATTERNS["private_key"]
    assert re.search(pat, "-----BEGIN RSA PRIVATE KEY-----")


def test_all_patterns_are_strings():
    for name, pat in PATTERNS.items():
        assert isinstance(name, str)
        assert isinstance(pat, str)
        assert len(pat) > 0


# --- triage / confidence

import asyncio  # noqa: E402
import base64  # noqa: E402
import json  # noqa: E402

import pytest  # noqa: E402
from conftest import FakeResp  # noqa: E402

from recon.modules.secrets import (  # noqa: E402
    classify,
    filter_by_confidence,
    find_secrets,
    scan_secrets,
    shannon_entropy,
)

REAL_GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz1A2"
REAL_AWS = "AKIA" + "Q3EGRWZ7T5HN2XKD"


def _jwt(header: dict) -> str:
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc(header)}.{enc({'sub': '1234567890', 'role': 'anon'})}.c2lnbmF0dXJlLXZhbHVl"


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("aB3dE5fG7hJ9kL1m") == 4.0


def test_docs_example_and_placeholders_are_dropped():
    assert classify("aws_access_key", "AKIAIOSFODNN7EXAMPLE") is None
    assert classify("github_pat", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") is None
    assert (
        classify("generic_api_key", 'api_key: "YOUR_API_KEY_HERE_1"', "YOUR_API_KEY_HERE_1") is None
    )
    assert classify("stripe_key", "sk_" + "live_" + "0" * 24) is None


def test_high_signal_formats_are_high():
    assert classify("aws_access_key", REAL_AWS) == ("high", "provider-specific key format")
    assert classify("github_pat", REAL_GH)[0] == "high"
    assert classify("private_key", "-----BEGIN RSA PRIVATE KEY-----")[0] == "high"


def test_stripe_live_vs_test():
    # Synthetic value, assembled at runtime so secret scanners don't flag the test file
    fake = "".join(chr(ord("a") + (i * 7) % 26) + str(i % 10) for i in range(12))
    assert classify("stripe_key", "sk_" + "live_" + fake)[0] == "high"
    assert classify("stripe_key", "sk_" + "test_" + fake) == (
        "low",
        "Stripe test-mode key",
    )


def test_google_key_is_medium_with_hint():
    conf, reason = classify("google_api", "AIza" + "SyD3k9Qm2Zx7Lp4Wn8Rt1Vb6Hc5Jf0Ga2Ke")
    assert conf == "medium"
    assert "restrictions" in reason


def test_jwt_must_decode():
    conf, reason = classify("jwt", _jwt({"alg": "HS256", "typ": "JWT"}))
    assert conf == "low" and "alg=HS256" in reason
    assert classify("jwt", "eyJnotbase64atall.eyJzdWIiOiIxMjM0.c2lnbmF0dXJl") is None
    assert classify("jwt", _jwt({"typ": "JWT"})) is None  # no alg — not a JWT header


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("passwordResetTokenField", False),  # identifier: no digits
        ("1234567890123456", False),  # digits only
        ("aaaa1111aaaa1111", False),  # low entropy
        ("k8Zq2Lw9Xv4Rt7Np3Ms6", True),
    ],
)
def test_generic_key_needs_random_value(value, kept):
    assert (classify("generic_api_key", f'secret: "{value}"', value) is not None) is kept


def test_find_secrets_dedupes_and_classifies():
    body = f'a="{REAL_GH}"; b="{REAL_GH}"; key="AKIAIOSFODNN7EXAMPLE"; x={REAL_AWS}'
    found = find_secrets("https://x.com/app.js", body)
    assert [(f.pattern, f.confidence) for f in found] == [
        ("aws_access_key", "high"),
        ("github_pat", "high"),
    ]


def test_new_patterns_detected():
    body = "\n".join(
        [
            "glpat-" + "Ab3De5Gh7Jk9Mn1Pq2Rs",
            "npm_" + "Ab3De5Gh7Jk9Mn1Pq2Rs4Tu6Vw8Xy0Za1Bc2De",
            "https://hooks.slack.com/services/" + "T01ABCD2E/B03FGHI4J/k5LmN6oPq7RsT8uV",
            "github_pat_" + "11ABCDEFG0" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6",
        ]
    )
    names = {f.pattern for f in find_secrets("u", body)}
    assert {"gitlab_pat", "npm_token", "slack_webhook", "github_fine_grained"} <= names


def test_filter_by_confidence():
    findings = [{"confidence": "high"}, {"confidence": "medium"}, {"confidence": "low"}, {}]
    assert len(filter_by_confidence(findings, "low")) == 4
    assert len(filter_by_confidence(findings, "medium")) == 3  # missing → medium (old results)
    assert filter_by_confidence(findings, "high") == [{"confidence": "high"}]


def test_scan_secrets_sorted_by_confidence(fake_http):
    body = f'var t="{_jwt({"alg": "HS256"})}"; var g="{REAL_GH}";'
    fake_http({"https://x.com/app.js": FakeResp(200, body)})
    found = asyncio.run(scan_secrets(["https://x.com/app.js"]))
    assert [f["confidence"] for f in found] == ["high", "low"]
    assert {"url", "pattern", "match", "confidence", "reason"} <= set(found[0])


@pytest.mark.asyncio
async def test_run_one_applies_min_confidence(tmp_path, monkeypatch):
    from recon.batch import TargetConfig
    from recon.cli import run_one

    async def fake_wayback(domain, errors):
        return ["https://x.com/app.js"]

    async def fake_scan(urls, **_):
        return [
            {"url": urls[0], "pattern": "github_pat", "match": "g", "confidence": "high"},
            {"url": urls[0], "pattern": "jwt", "match": "j", "confidence": "low"},
        ]

    monkeypatch.setattr("recon.cli.fetch_wayback_urls", fake_wayback)
    monkeypatch.setattr("recon.cli.scan_secrets", fake_scan)
    cfg = TargetConfig(
        domain="x.com",
        output=str(tmp_path / "x"),
        skip=["subdomains"],
        secrets_min_confidence="medium",
    )
    result = await run_one(cfg, no_html=True)
    assert [s["pattern"] for s in result["secrets"]] == ["github_pat"]


def test_batch_rejects_bad_min_confidence():
    from recon.batch import TargetConfig

    with pytest.raises(ValueError, match="secrets_min_confidence"):
        TargetConfig.from_dict({"domain": "a.com", "secrets_min_confidence": "urgent"})


def test_reports_show_confidence(tmp_path):
    from recon.reporting.html_report import write_html_report
    from recon.reporting.markdown import write_markdown_report

    results = {
        "target": "x.com",
        "secrets": [
            {"url": "u", "pattern": "jwt", "match": "j", "confidence": "low", "reason": "JWT"},
            {"url": "u", "pattern": "github_pat", "match": "g", "confidence": "high"},
            {"url": "u", "pattern": "old_result", "match": "o"},  # pre-triage results.json
        ],
    }
    write_markdown_report(results, tmp_path / "r.md")
    write_html_report(results, tmp_path / "r.html")
    md = (tmp_path / "r.md").read_text()
    assert md.index("| high | u | github_pat") < md.index("| low | u | jwt")
    assert "| — | u | old_result" in md
    assert "HIGH" in (tmp_path / "r.html").read_text()


def test_monitor_alerts_skip_low_confidence_secrets():
    from recon.monitor import alert_items

    delta = {
        "added": {
            "secrets": [
                {"pattern": "jwt", "url": "u", "confidence": "low"},
                {"pattern": "github_pat", "url": "u", "confidence": "high"},
            ]
        }
    }
    assert alert_items(delta) == {"secrets": ["github_pat (high) in u"]}
