from recon.modules.nuclei import nuclei_available, run_nuclei


def test_nuclei_available_returns_bool():
    assert isinstance(nuclei_available(), bool)


def test_run_nuclei_empty_hosts():
    import asyncio

    res = asyncio.run(run_nuclei([]))
    assert res == []


def test_run_nuclei_no_binary_returns_warning():
    """If nuclei is not installed, returns a warning dict instead of failing."""
    import asyncio

    from recon.modules.nuclei import NUCLEI_BIN

    if NUCLEI_BIN is not None:
        # skip when installed; we want to test the missing-binary path
        return
    hosts = [{"url": "https://example.com/"}]
    res = asyncio.run(run_nuclei(hosts, timeout=5))
    assert len(res) == 1
    assert "_warning" in res[0]
    assert "nuclei" in res[0]["_warning"].lower()


def _fake_nuclei(tmp_path, script: str):
    path = tmp_path / "nuclei"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(0o755)
    return str(path)


def test_run_nuclei_uses_v3_flags_and_streams(tmp_path, monkeypatch):
    import asyncio

    from recon.modules import nuclei

    # Fails like real nuclei v3 does if the removed -json flag is passed
    bin_path = _fake_nuclei(
        tmp_path,
        'for a in "$@"; do\n'
        '  case "$a" in -json|-no-update-check) echo "flag provided but not defined: $a" >&2; exit 2;; esac\n'
        "done\n"
        'echo \'{"template-id": "t1", "info": {"severity": "high"}}\'\n'
        'echo \'{"template-id": "t2", "info": {"severity": "critical"}}\'\n',
    )
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", bin_path)
    seen = []
    res = asyncio.run(
        nuclei.run_nuclei([{"url": "https://x.com/"}], timeout=10, on_finding=seen.append)
    )
    assert [f["template-id"] for f in res] == ["t1", "t2"]
    assert seen == res


def test_run_nuclei_nonzero_exit_is_reported(tmp_path, monkeypatch):
    import asyncio

    from recon.modules import nuclei

    bin_path = _fake_nuclei(tmp_path, 'echo "could not load templates" >&2\nexit 1\n')
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", bin_path)
    res = asyncio.run(nuclei.run_nuclei([{"url": "https://x.com/"}], timeout=10))
    assert res == [{"_warning": "nuclei exited with code 1: could not load templates"}]


def test_run_nuclei_timeout_kills_process(tmp_path, monkeypatch):
    import asyncio

    from recon.modules import nuclei

    bin_path = _fake_nuclei(tmp_path, 'echo \'{"template-id": "t1"}\'\nexec sleep 30\n')
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", bin_path)
    res = asyncio.run(nuclei.run_nuclei([{"url": "https://x.com/"}], timeout=1))
    assert res[0] == {"template-id": "t1"}
    assert "timed out" in res[-1]["_warning"]


def test_run_nuclei_passes_templates_and_tags(tmp_path, monkeypatch):
    import asyncio
    import json

    from recon.modules import nuclei

    # Echo argv back as a finding so the test can inspect the command line
    bin_path = _fake_nuclei(
        tmp_path,
        'python3 -c \'import json,sys; print(json.dumps({"argv": sys.argv[1:]}))\' "$@"\n',
    )
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", bin_path)
    res = asyncio.run(
        nuclei.run_nuclei(
            [{"url": "https://x.com/"}], templates=["http/cves/"], tags=["cve", "rce"], timeout=10
        )
    )
    argv = res[0]["argv"]
    assert argv[argv.index("-t") + 1] == "http/cves/"
    assert argv[argv.index("-tags") + 1] == "cve,rce"
    assert "-jsonl" in argv and "-disable-update-check" in argv
    json.dumps(res)


def _argv_of(tmp_path, monkeypatch, **kw):
    import asyncio

    from recon.modules import nuclei

    bin_path = _fake_nuclei(
        tmp_path,
        'python3 -c \'import json,sys; print(json.dumps({"argv": sys.argv[1:]}))\' "$@"\n',
    )
    monkeypatch.setattr(nuclei, "NUCLEI_BIN", bin_path)
    res = asyncio.run(nuclei.run_nuclei([{"url": "https://x.com/"}], timeout=10, **kw))
    return res[0]["argv"]


def test_default_scan_filters_to_critical_high_medium(tmp_path, monkeypatch):
    argv = _argv_of(tmp_path, monkeypatch)
    assert argv[argv.index("-severity") + 1] == "critical,high,medium"


def test_explicit_tags_are_not_severity_filtered(tmp_path, monkeypatch):
    """`tech` templates are all severity info; filtering would drop every one."""
    argv = _argv_of(tmp_path, monkeypatch, tags=["tech"])
    assert "-severity" not in argv


def test_explicit_severity_still_applies_with_tags(tmp_path, monkeypatch):
    argv = _argv_of(tmp_path, monkeypatch, tags=["tech"], severity=["info"])
    assert argv[argv.index("-severity") + 1] == "info"
