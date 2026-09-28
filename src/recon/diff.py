"""Diff mode — compare two scan results and produce a delta report.

Compares per-collection: subdomains, alive, urls, secrets, header findings,
nuclei findings, CORS reflection map. Returns:
    {
        "added": {...},       # new in 'current' vs 'baseline'
        "removed": {...},     # gone from 'current'
        "unchanged_counts": {...},
        "severity_delta": {"critical": +2, "high": 0, ...},
        "summary": "..."
    }
"""

from __future__ import annotations

from typing import Any


def _sevs(items: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for it in items or []:
        if not isinstance(it, dict) or it.get("_warning"):
            continue
        sev = ((it.get("info") or {}).get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def diff_results(baseline: dict, current: dict) -> dict[str, Any]:
    """Return the delta between two scan results."""
    keys = ("subdomains", "alive", "urls", "secrets", "header_findings")
    added: dict[str, list] = {k: [] for k in keys}
    removed: dict[str, list] = {k: [] for k in keys}
    unchanged: dict[str, int] = {}

    def _to_keys(items: list, kind: str) -> set:
        """Extract a hashable identity key from each item."""
        out: set = set()
        for it in items:
            if isinstance(it, dict):
                key = it.get("url") or it.get("host")
                if not key:
                    if kind == "secrets":
                        key = f"{it.get('pattern', '')}|{it.get('match', '')}"
                    else:
                        key = repr(sorted(it.items()))
                out.add(key)
            else:
                out.add(str(it))
        return out

    def _to_map(items: list, kind: str) -> dict:
        out: dict = {}
        for it in items:
            if isinstance(it, dict):
                if kind == "header_findings":
                    key = f"{it.get('host', '')}|{it.get('check', '')}|{it.get('detail', '')}"
                else:
                    key = it.get("url") or it.get("host")
                if not key:
                    if kind == "secrets":
                        key = f"{it.get('pattern', '')}|{it.get('match', '')}"
                    else:
                        key = repr(sorted(it.items()))
                out[key] = it
            else:
                out[str(it)] = it
        return out

    for k in keys:
        b_items = baseline.get(k, []) or []
        c_items = current.get(k, []) or []
        b_map = _to_map(b_items, k)
        c_map = _to_map(c_items, k)
        b_keys = set(b_map)
        c_keys = set(c_map)
        added[k] = [c_map[key] for key in c_keys - b_keys]
        removed[k] = [b_map[key] for key in b_keys - c_keys]
        unchanged[k] = len(b_keys & c_keys)

    # Nuclei severity delta
    b_sev = _sevs(baseline.get("nuclei", []) or [])
    c_sev = _sevs(current.get("nuclei", []) or [])
    sev_delta = {k: c_sev.get(k, 0) - b_sev.get(k, 0) for k in c_sev}
    # Drop zero entries for a cleaner delta
    sev_delta = {k: v for k, v in sev_delta.items() if v != 0}

    # CORS reflective diff — only hosts that actually reflect, not every probed host
    def _reflecting(res: dict) -> set:
        return {
            host
            for host, v in (res.get("cors_reflective") or {}).items()
            if isinstance(v, dict) and v.get("reflects")
        }

    b_cors = _reflecting(baseline)
    c_cors = _reflecting(current)
    cors_added = sorted(c_cors - b_cors)
    cors_removed = sorted(b_cors - c_cors)

    summary_parts = []
    for k in keys:
        if added[k]:
            summary_parts.append(f"+{len(added[k])} {k}")
        if removed[k]:
            summary_parts.append(f"-{len(removed[k])} {k}")
    if cors_added:
        summary_parts.append(f"+{len(cors_added)} cors-reflective")
    if cors_removed:
        summary_parts.append(f"-{len(cors_removed)} cors-reflective")
    if sev_delta.get("critical", 0) > 0:
        summary_parts.append(f"+{sev_delta['critical']} critical nuclei")

    return {
        "target": current.get("target", "?"),
        "baseline_timestamp": baseline.get("timestamp"),
        "current_timestamp": current.get("timestamp"),
        "added": added,
        "removed": removed,
        "unchanged_counts": unchanged,
        "cors_reflective_added": cors_added,
        "cors_reflective_removed": cors_removed,
        "severity_delta": sev_delta,
        "summary": " · ".join(summary_parts) if summary_parts else "no changes",
    }
