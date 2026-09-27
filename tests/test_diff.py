from recon.diff import diff_results


def _res(target, **kw):
    base = {
        "target": target,
        "subdomains": [],
        "alive": [],
        "urls": [],
        "secrets": [],
        "nuclei": [],
    }
    base.update(kw)
    return base


def test_diff_no_changes():
    b = _res("x.com", subdomains=["a.x.com"])
    c = _res("x.com", subdomains=["a.x.com"])
    d = diff_results(b, c)
    assert d["added"]["subdomains"] == []
    assert d["removed"]["subdomains"] == []
    assert d["unchanged_counts"]["subdomains"] == 1
    assert d["summary"] == "no changes"


def test_diff_added_subdomains():
    b = _res("x.com", subdomains=["a.x.com"])
    c = _res("x.com", subdomains=["a.x.com", "b.x.com"])
    d = diff_results(b, c)
    assert "b.x.com" in d["added"]["subdomains"]
    assert d["unchanged_counts"]["subdomains"] == 1


def test_diff_removed_subdomains():
    b = _res("x.com", subdomains=["a.x.com", "b.x.com"])
    c = _res("x.com", subdomains=["a.x.com"])
    d = diff_results(b, c)
    assert "b.x.com" in d["removed"]["subdomains"]
    assert d["added"]["subdomains"] == []


def test_diff_secrets_added():
    b = _res("x.com")
    c = _res(
        "x.com",
        secrets=[
            {"url": "https://x.com/a.js", "pattern": "aws_access_key", "match": "AKIA1234"},
        ],
    )
    d = diff_results(b, c)
    assert len(d["added"]["secrets"]) == 1
    assert "AKIA1234" in str(d["added"]["secrets"])


def test_diff_severity_delta():
    b = _res("x.com", nuclei=[{"info": {"severity": "critical"}}])
    c = _res(
        "x.com",
        nuclei=[
            {"info": {"severity": "critical"}},
            {"info": {"severity": "high"}},
            {"info": {"severity": "high"}},
        ],
    )
    d = diff_results(b, c)
    # zero deltas are dropped
    assert "critical" not in d["severity_delta"]
    assert d["severity_delta"]["high"] == 2  # two new highs


def test_diff_severity_delta_negative():
    b = _res(
        "x.com",
        nuclei=[
            {"info": {"severity": "critical"}},
            {"info": {"severity": "high"}},
        ],
    )
    c = _res("x.com", nuclei=[{"info": {"severity": "critical"}}])
    d = diff_results(b, c)
    assert d["severity_delta"]["high"] == -1


def test_diff_cors_reflective_diff():
    b = _res("x.com", cors_reflective={"a.x.com": {"reflects": True}})
    c = _res(
        "x.com",
        cors_reflective={
            "a.x.com": {"reflects": True},
            "b.x.com": {"reflects": True},
        },
    )
    d = diff_results(b, c)
    assert "b.x.com" in d["cors_reflective_added"]
    assert "a.x.com" not in d["cors_reflective_added"]


def test_diff_warning_dicts_excluded_from_severity():
    b = _res("x.com", nuclei=[{"_warning": "nuclei missing"}])
    c = _res("x.com", nuclei=[])
    d = diff_results(b, c)
    # No real findings on either side → no delta entries
    assert d["severity_delta"] == {}


def test_diff_summary_format():
    b = _res("x.com")
    c = _res("x.com", subdomains=["a.x.com"], nuclei=[{"info": {"severity": "critical"}}])
    d = diff_results(b, c)
    assert "+1 subdomains" in d["summary"]
    assert "+1 critical nuclei" in d["summary"]


def test_diff_target_propagated():
    d = diff_results(_res("baseline.com"), _res("current.com"))
    assert d["target"] == "current.com"


def test_diff_cors_ignores_non_reflecting_hosts():
    """cors_reflective holds every probed host; only reflecting ones count."""
    b = _res("x.com", cors_reflective={"a.x.com": {"reflects": False}})
    c = _res(
        "x.com",
        cors_reflective={"a.x.com": {"reflects": False}, "b.x.com": {"reflects": False}},
    )
    d = diff_results(b, c)
    assert d["cors_reflective_added"] == []
    assert d["summary"] == "no changes"
