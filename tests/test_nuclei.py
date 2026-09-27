from pathlib import Path

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
