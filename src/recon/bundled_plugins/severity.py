"""Bundled plugins shipped with cyber-recon.

These are always available — no filesystem discovery required.
"""

from ..plugins import register


async def severity_counter(target, results, **_):
    """Tally finding severity counts into results['severity_summary']."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # nuclei findings
    for f in results.get("nuclei", []) or []:
        if not isinstance(f, dict) or f.get("_warning"):
            continue
        sev = (f.get("info", {}) or {}).get("severity", "info") or "info"
        counts[sev.lower()] = counts.get(sev.lower(), 0) + 1

    # Security header audit + TLS check
    for f in (results.get("header_findings") or []) + (results.get("tls_findings") or []):
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # CORS reflection issues
    for v in (results.get("cors_reflective") or {}).values():
        if v.get("reflects"):
            counts["high"] += 1

    results["severity_summary"] = counts
    return results


register(
    "severity_counter",
    severity_counter,
    description="Tally finding severities into a summary count.",
    active_default=True,
    source="bundled",
)
