"""Monitoring mode — keep a scan history per target and surface only what is new.

Layout inside a target's output directory::

    results.json              latest scan (as before)
    diff.json                 delta vs the previous scan
    history/<timestamp>.json  one snapshot per scan, oldest pruned past ``keep``

Scheduling is left to cron / systemd timers / CI: each run is one scan.
"""

from __future__ import annotations

import json
from pathlib import Path

HISTORY_DIR = "history"
DEFAULT_KEEP = 30
ALERT_LIMIT = 10  # items listed per category in a notification


def _history(out_dir: Path) -> Path:
    return out_dir / HISTORY_DIR


def latest_snapshot(out_dir: Path) -> dict | None:
    """Most recent saved scan, falling back to a pre-monitoring results.json."""
    snaps = sorted(_history(out_dir).glob("*.json"))
    candidates = [snaps[-1]] if snaps else []
    candidates.append(out_dir / "results.json")
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return data
    return None


def save_snapshot(out_dir: Path, results: dict, keep: int = DEFAULT_KEEP) -> Path:
    """Write ``results`` into history and prune to the newest ``keep`` snapshots."""
    hist = _history(out_dir)
    hist.mkdir(parents=True, exist_ok=True)
    stamp = str(results.get("timestamp") or "unknown").replace(":", "-").replace("+", "_")
    # Fixed-width counter so names sort chronologically when scans share a
    # timestamp. Continue past the highest existing counter rather than reusing
    # a gap, since pruning deletes the lowest ones first.
    used = [
        int(counter)
        for p in hist.glob(f"{stamp}_*.json")
        if (counter := p.stem.rsplit("_", 1)[-1]).isdigit()
    ]
    path = hist / f"{stamp}_{max(used, default=-1) + 1:03d}.json"
    path.write_text(json.dumps(results, indent=2, default=str))
    if keep > 0:
        for old in sorted(hist.glob("*.json"))[:-keep]:
            old.unlink()
    return path


def alert_items(delta: dict) -> dict[str, list[str]]:
    """New findings worth a notification, as short display strings per category.

    Removals, info-level header findings and low-confidence secrets are left
    out on purpose: they are in diff.json, but not something to be woken up for.
    """
    added = delta.get("added") or {}
    items: dict[str, list[str]] = {
        "subdomains": sorted(str(s) for s in added.get("subdomains") or []),
        "live hosts": sorted(
            f"{h.get('url', h.get('host', '?'))} [{h.get('status', '?')}]"
            for h in added.get("alive") or []
        ),
        "secrets": [
            f"{s.get('pattern', '?')} ({s.get('confidence', '?')}) in {s.get('url', '?')}"
            for s in added.get("secrets") or []
            if s.get("confidence") != "low"
        ],
        "header issues": [
            f"{f.get('host', '?')}: {f.get('check', '?')} ({f.get('severity', '?')})"
            for f in added.get("header_findings") or []
            if f.get("severity") != "info"
        ],
        "nuclei": [
            f"{(f.get('info') or {}).get('severity', '?')}: {f.get('template-id', '?')} "
            f"at {f.get('matched-at', '?')}"
            for f in added.get("nuclei") or []
        ],
        "CORS reflection": list(delta.get("cors_reflective_added") or []),
    }
    return {k: v for k, v in items.items() if v}


def format_alert(target: str, alerts: dict[str, list[str]], limit: int = ALERT_LIMIT) -> str:
    """Plain-text alert body (Markdown-ish, fine for Slack and Discord)."""
    lines = [f"New since last scan of {target}:"]
    for category, entries in alerts.items():
        lines.append(f"*{category}* (+{len(entries)})")
        lines.extend(f"• {e}" for e in entries[:limit])
        if len(entries) > limit:
            lines.append(f"• … and {len(entries) - limit} more (see diff.json)")
    return "\n".join(lines)
