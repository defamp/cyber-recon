from recon.modules.subdomains import _extract_unique


def test_extract_unique_strips_wildcards(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "*.example.com" not in result
    assert "*" not in "".join(result)


def test_extract_unique_filters_unrelated(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "unrelated.org" not in result


def test_extract_unique_keeps_subdomains(sample_hosts):
    result = _extract_unique("example.com", sample_hosts)
    assert "a.example.com" in result
    assert "foo.bar.example.com" in result


def test_extract_unique_dedupes():
    hosts = ["a.example.com", "a.example.com", "b.example.com"]
    result = _extract_unique("example.com", hosts)
    assert len(result) == 2


def test_extract_unique_lowercases():
    hosts = ["A.Example.COM"]
    result = _extract_unique("example.com", hosts)
    assert result == ["a.example.com"]


def test_extract_unique_empty():
    assert _extract_unique("example.com", []) == []
