import asyncio

import pytest

from recon.plugins import (
    _ensure_bundled_loaded,
    discover,
    get_plugin,
    list_plugins,
    register,
    reset,
    run_plugins,
    unregister,
)


def setup_function(_):
    reset()


def teardown_function(_):
    reset()


def test_register_and_list():
    async def fn(target, results, **kw):
        return {"x": 1}

    register("alpha", fn, description="test plugin", active_default=True)
    plugins = list_plugins()
    assert any(p.name == "alpha" for p in plugins)


def test_register_validates_name():
    async def fn(t, r, **k):
        return None

    with pytest.raises(ValueError):
        register("", fn)
    with pytest.raises(ValueError):
        register("bad name with spaces", fn)
    with pytest.raises(ValueError):
        register("bad/name", fn)


def test_unregister():
    async def fn(t, r, **k):
        return None

    register("beta", fn)
    assert get_plugin("beta") is not None
    assert unregister("beta") is True
    assert get_plugin("beta") is None
    assert unregister("beta") is False


def test_bundled_plugin_loaded_on_list():
    _ensure_bundled_loaded()
    plugins = list_plugins()
    assert any(p.name == "severity_counter" and p.source == "bundled" for p in plugins)


def test_run_default_plugins_merges_into_results():
    results = {
        "target": "x",
        "nuclei": [
            {"info": {"severity": "critical"}},
            {"info": {"severity": "high"}},
            {"_warning": "ignored"},
        ],
    }
    out = asyncio.run(run_plugins(results))
    assert "severity_summary" in out
    assert out["severity_summary"]["critical"] == 1
    assert out["severity_summary"]["high"] == 1


def test_run_specific_plugins_by_name():
    async def custom(target, results, **kw):
        results["custom_marker"] = True
        return results

    register("custom", custom, active_default=False)
    results = {"target": "y"}
    asyncio.run(run_plugins(results, names=["custom"]))
    assert results.get("custom_marker") is True


def test_run_plugins_swallows_exceptions(caplog):
    async def broken(target, results, **kw):
        raise RuntimeError("boom")

    register("broken", broken, active_default=False)
    results = {"target": "z"}
    out = asyncio.run(run_plugins(results, names=["broken"]))
    assert out == results  # unchanged, no exception raised


def test_discover_loads_user_plugin(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "demo.py").write_text(
        "from recon.plugins import register\n"
        "async def run(target, results, **kw):\n"
        "    results['demo_data'] = 'ok'\n"
        "    return results\n"
        "register('demo', run, description='demo plugin', active_default=False)\n"
    )
    monkeypatch.setattr("recon.plugins.PLUGIN_DIR", plugin_dir)
    loaded = discover()
    assert "demo" in loaded
    p = get_plugin("demo")
    assert p is not None
    assert p.description == "demo plugin"


def test_discover_handles_missing_dir(tmp_path, monkeypatch):
    missing = tmp_path / "nope"
    monkeypatch.setattr("recon.plugins.PLUGIN_DIR", missing)
    assert discover() == []


def test_discover_skips_underscore_files(tmp_path, monkeypatch):
    d = tmp_path / "plugins"
    d.mkdir()
    (d / "_skip.py").write_text("raise RuntimeError('should not be loaded')")
    monkeypatch.setattr("recon.plugins.PLUGIN_DIR", d)
    assert discover() == []
