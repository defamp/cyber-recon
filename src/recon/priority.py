"""Priority score — rank live hosts by how promising they look for manual testing.

The score is a transparent sum of weighted signals, each listed in
``reasons``. The weights are judgment calls, not calibrated on data: treat the
ranking as "where to look first", never as a severity.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse

SECRET_POINTS = {"high": 40, "medium": 15, "low": 3}
NUCLEI_POINTS = {"critical": 50, "high": 30, "medium": 12, "low": 4}
CORS_REFLECT_POINTS = 25
CORS_CREDENTIALS_POINTS = 15
FINDING_POINTS = {"medium": 8, "low": 3}  # header + TLS findings
FINDING_CAP = 15  # missing headers alone should not outrank a real signal
KEYWORD_POINTS = 8
KEYWORD_CAP = 16
AUTH_STATUS_POINTS = 5  # 401/403: an auth boundary worth a look
ERROR_STATUS_POINTS = 3
NEW_HOST_POINTS = 15

KEYWORDS = {
    "admin", "login", "signin", "sso", "auth", "dashboard", "portal", "console",
    "jenkins", "gitlab", "grafana", "kibana", "jira", "confluence", "phpmyadmin",
    "swagger", "graphql", "api", "staging", "stage", "dev", "test", "uat", "qa",
    "internal", "intranet", "vpn", "backup", "old", "legacy", "beta", "debug",
}  # fmt: skip


def _host_of(value: str) -> str:
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.lower()


def _keywords(host: str, title: str) -> list[str]:
    # Whole labels/words only: "latest" must not count as "test"
    words = set(re.split(r"[.\-_]", host.lower())) | set(re.findall(r"[a-z]+", title.lower()))
    return sorted(words & KEYWORDS)


def score_hosts(results: dict, new_hosts: set[str] | None = None) -> list[dict]:
    """Return every live host with its score and reasons, highest first."""
    new_hosts = new_hosts or set()
    by_host: dict[str, list[tuple[int, str]]] = defaultdict(list)

    for s in results.get("secrets") or []:
        conf = s.get("confidence", "medium")
        pts = SECRET_POINTS.get(conf, 0)
        if pts:
            by_host[_host_of(s.get("url", ""))].append(
                (pts, f"{conf} secret: {s.get('pattern', '?')}")
            )

    for f in results.get("nuclei") or []:
        if f.get("_warning"):
            continue
        sev = ((f.get("info") or {}).get("severity") or "info").lower()
        pts = NUCLEI_POINTS.get(sev, 0)
        if pts:
            host = _host_of(f.get("matched-at") or f.get("host") or "")
            by_host[host].append((pts, f"nuclei {sev}: {f.get('template-id', '?')}"))

    for host, v in (results.get("cors_reflective") or {}).items():
        if isinstance(v, dict) and v.get("reflects"):
            by_host[host.lower()].append((CORS_REFLECT_POINTS, "reflects arbitrary Origin"))
            if (v.get("acac") or "").lower() == "true":
                by_host[host.lower()].append((CORS_CREDENTIALS_POINTS, "…with credentials"))

    finding_pts: dict[str, int] = defaultdict(int)
    for f in (results.get("header_findings") or []) + (results.get("tls_findings") or []):
        finding_pts[(f.get("host") or "").lower()] += FINDING_POINTS.get(f.get("severity"), 0)

    ranked = []
    for h in results.get("alive") or []:
        host = (h.get("host") or "").lower()
        reasons = list(by_host.get(host, []))
        if pts := min(finding_pts.get(host, 0), FINDING_CAP):
            reasons.append((pts, "header/TLS weaknesses"))
        if words := _keywords(host, h.get("title") or ""):
            reasons.append(
                (min(KEYWORD_POINTS * len(words), KEYWORD_CAP), f"keywords: {', '.join(words)}")
            )
        status = h.get("status") or 0
        if status in (401, 403):
            reasons.append((AUTH_STATUS_POINTS, f"auth wall ({status})"))
        elif status >= 500:
            reasons.append((ERROR_STATUS_POINTS, f"server error ({status})"))
        if host in new_hosts:
            reasons.append((NEW_HOST_POINTS, "new since last scan"))
        reasons.sort(key=lambda r: -r[0])
        ranked.append(
            {
                "host": h.get("host", ""),
                "url": h.get("url", ""),
                "score": sum(p for p, _ in reasons),
                "reasons": [f"+{p} {why}" for p, why in reasons],
            }
        )
    ranked.sort(key=lambda r: (-r["score"], r["host"]))
    return ranked
