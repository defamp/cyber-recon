"""Plugin loader — auto-discover recon modules from ~/.recon/plugins/.

A plugin is a Python module exposing async functions matching the signature:
    async def run(target: str, results: dict, **kwargs) -> dict | None:

The function receives the shared results dict and may add new keys. Return
either a dict to merge into results, or None to leave results unchanged.

Bundled plugins live in ``recon.bundled_plugins`` and are imported
automatically on first use. User plugins are auto-discovered from
``~/.recon/plugins/``.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

PLUGIN_DIR = Path.home() / ".recon" / "plugins"

PluginFn = Callable[..., Awaitable[dict | None]]


@dataclass
class PluginSpec:
    name: str
    fn: PluginFn
    description: str = ""
    active_default: bool = False
    source: str = "bundled"  # bundled | user

    def __post_init__(self):
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ValueError(f"invalid plugin name: {self.name!r}")


_REGISTRY: dict[str, PluginSpec] = {}
_BUNDLED_LOADED = False


def _ensure_bundled_loaded() -> None:
    """Import every module in recon.bundled_plugins to trigger their register() calls."""
    global _BUNDLED_LOADED
    if _BUNDLED_LOADED:
        return
    try:
        pkg = importlib.import_module("recon.bundled_plugins")
        for _finder, name, _is_pkg in pkgutil.iter_modules(pkg.__path__):
            importlib.import_module(f"recon.bundled_plugins.{name}")
    except Exception as exc:
        log.warning("failed to load bundled plugins: %s", exc)
    # Mark as loaded regardless of whether the import succeeded — we don't
    # want to keep retrying on every list_plugins() call. New bundled
    # plugins require a process restart (or an explicit reset()).
    _BUNDLED_LOADED = True


def register(
    name: str,
    fn: PluginFn,
    *,
    description: str = "",
    active_default: bool = False,
    source: str = "user",
) -> PluginSpec:
    """Register a plugin. Replaces any existing plugin with the same name."""
    spec = PluginSpec(
        name=name, fn=fn, description=description, active_default=active_default, source=source
    )
    _REGISTRY[name] = spec
    return spec


def unregister(name: str) -> bool:
    return _REGISTRY.pop(name, None) is not None


def list_plugins() -> list[PluginSpec]:
    _ensure_bundled_loaded()
    return sorted(_REGISTRY.values(), key=lambda p: p.name)


def get_plugin(name: str) -> PluginSpec | None:
    _ensure_bundled_loaded()
    return _REGISTRY.get(name)


def reset() -> None:
    """Clear all plugins. Test helper.

    Also evicts bundled plugin modules from sys.modules so they re-register
    cleanly on next access.
    """
    global _BUNDLED_LOADED
    _REGISTRY.clear()
    _BUNDLED_LOADED = False
    # Drop cached bundled modules so their top-level register() runs again
    for name in list(sys.modules):
        if name.startswith("recon.bundled_plugins."):
            del sys.modules[name]


def discover() -> list[str]:
    """Discover and import plugin modules from ~/.recon/plugins/.

    Returns the list of plugin names (basenames without .py) that are now
    registered as a result of this call. Plugins that expose a top-level
    ``run()`` coroutine function are auto-registered if not already.
    Errors during import are logged but do not raise.
    """
    if not PLUGIN_DIR.exists():
        return []
    if str(PLUGIN_DIR) not in sys.path:
        sys.path.insert(0, str(PLUGIN_DIR))

    loaded: list[str] = []
    for path in sorted(PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = f"recon_user_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as exc:
            log.warning("failed to load plugin %s: %s", path, exc)
            continue
        # After import: register if not already (the module may have called
        # register() explicitly during its body).
        already_known = path.stem in _REGISTRY
        run = getattr(mod, "run", None)
        if run is not None and callable(run) and not already_known:
            register(
                path.stem,
                run,  # type: ignore[arg-type]
                description=(getattr(mod, "__doc__", "") or "").strip().splitlines()[0]
                if getattr(mod, "__doc__", "")
                else "",
                active_default=getattr(mod, "ACTIVE_DEFAULT", False),
                source="user",
            )
        if path.stem in _REGISTRY:
            loaded.append(path.stem)
    return loaded


async def run_plugins(results: dict, names: list[str] | None = None) -> dict:
    """Run the named (or all active_default) plugins against the results dict.

    Each plugin's return value is merged into results. The results dict
    is mutated in place AND returned.
    """
    _ensure_bundled_loaded()
    targets = (
        [_REGISTRY[n] for n in names if n in _REGISTRY]
        if names
        else [p for p in list_plugins() if p.active_default]
    )
    for plugin in targets:
        try:
            out = await plugin.fn(results.get("target", ""), results)
            if isinstance(out, dict):
                results.update(out)
        except Exception as exc:
            log.warning("plugin %s failed: %s", plugin.name, exc)
    return results
