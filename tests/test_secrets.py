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


def test_filter_js_urls_dedupes_query_and_scheme_variants():
    urls = [
        "http://x.com/app.js?v=1",
        "https://x.com/app.js?v=2",
        "http://x.com:80/app.js",
        "https://x.com/other.js",
    ]
    assert _filter_js_urls(urls) == ["http://x.com/app.js?v=1", "https://x.com/other.js"]


def test_group_findings_merges_and_ranks_by_confidence():
    from recon.modules.secrets import Finding, _group_findings

    findings = [
        Finding("https://x.com/a.js", "generic_api_key", 'apikey="abcdefghijklmnop"'),
        Finding("https://x.com/b.js", "generic_api_key", 'apikey="abcdefghijklmnop"'),
        Finding("https://x.com/c.js", "aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        Finding("https://x.com/a.js", "generic_api_key", 'apikey="abcdefghijklmnop"'),
    ]
    out = _group_findings(findings)
    assert [(f["pattern"], f["confidence"]) for f in out] == [
        ("aws_access_key", "high"),
        ("generic_api_key", "low"),
    ]
    generic = out[1]
    assert generic["occurrences"] == 3
    assert generic["urls"] == ["https://x.com/a.js", "https://x.com/b.js"]
    assert generic["url"] == "https://x.com/a.js"


def test_every_pattern_has_a_confidence():
    from recon.modules.secrets import CONFIDENCE

    assert set(CONFIDENCE) == set(PATTERNS)
