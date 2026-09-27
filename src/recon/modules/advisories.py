"""Async GitHub advisory lookup for CVE enrichment.

Uses GitHub's REST Advisory Database (public, no auth required for limited
rate). Looks up CVEs found in nuclei findings and adds `gh_advisory` keys.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

ADVISORY_URL = "https://api.github.com/advisories/{ghsa_id}"
CVE_URL = "https://api.github.com/advisories?cve_id={cve_id}"
TIMEOUT = 10
CONCURRENCY = 5


def _extract_cves(finding: dict) -> list[str]:
    tags = (finding.get("info") or {}).get("tags") or []
    classification = (finding.get("info") or {}).get("classification") or {}
    out: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.upper().startswith("CVE-"):
            out.append(tag.upper())
    for k in ("cve", "cve-id", "cve-id-list"):
        v = classification.get(k) if isinstance(classification, dict) else None
        if isinstance(v, str) and v.upper().startswith("CVE-"):
            out.append(v.upper())
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, str) and x.upper().startswith("CVE-"):
                    out.append(x.upper())
    # also check template-id like CVE-2021-44228
    tid = finding.get("template-id") or ""
    if tid.upper().startswith("CVE-") and tid.upper() not in out:
        out.append(tid.upper())
    return list(dict.fromkeys(out))[:3]  # de-dupe, cap at 3


async def _lookup_cve(session: aiohttp.ClientSession, cve: str) -> dict[str, Any] | None:
    try:
        async with session.get(
            CVE_URL.format(cve_id=cve),
            headers={"Accept": "application/vnd.github+json", "User-Agent": "cyber-recon/0.1"},
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as r:
            if r.status == 404:
                return None
            if r.status != 200:
                return {"cve": cve, "_error": f"http {r.status}"}
            data = await r.json(content_type=None)
    except Exception as exc:
        return {"cve": cve, "_error": str(exc)}
    if not isinstance(data, list) or not data:
        return None
    item = data[0]
    return {
        "cve": cve,
        "ghsa_id": item.get("ghsa_id"),
        "summary": item.get("summary"),
        "severity": (item.get("severity") or "").lower() or None,
        "cvss": (item.get("cvss") or {}).get("score"),
        "published_at": item.get("published_at"),
        "html_url": item.get("html_url"),
    }


async def enrich_nuclei(findings: list[dict], *, max_concurrency: int = CONCURRENCY) -> list[dict]:
    """For each finding with a CVE, fetch advisory and attach gh_advisory."""
    sem = asyncio.Semaphore(max_concurrency)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyber-recon/0.1"}

    async with aiohttp.ClientSession(headers=headers) as session:

        async def task(f: dict) -> dict:
            async with sem:
                cves = _extract_cves(f)
                if not cves:
                    return f
                enriched = await asyncio.gather(*(_lookup_cve(session, c) for c in cves))
                enriched_clean = [e for e in enriched if e]
                if enriched_clean:
                    f = dict(f)
                    f["gh_advisory"] = enriched_clean
                return f

        out = await asyncio.gather(*(task(f) for f in findings))
    return out
