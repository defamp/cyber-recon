"""Markdown report writer."""

from datetime import UTC, datetime
from pathlib import Path

from ..modules.headers_audit import finding_sort_key


def scope_summary(results: dict) -> str:
    """One-line scope/rate description, or "" for older results without scope data."""
    scope = results.get("scope")
    if not scope:
        return ""
    oos = results.get("out_of_scope") or {}
    parts = [f"Scope: {scope.get('source', 'default')}"]
    if oos.get("subdomains"):
        parts.append(f"{len(oos['subdomains'])} out-of-scope subdomain(s) not probed")
    if oos.get("urls"):
        parts.append(f"{oos['urls']} out-of-scope URL(s) dropped")
    if scope.get("rate_limit"):
        parts.append(f"rate limit {scope['rate_limit']:g} req/s")
    return " · ".join(parts)


def write_markdown_report(results: dict, path: Path) -> None:
    target = results.get("target", "?")
    now = datetime.now(UTC).isoformat(timespec="seconds")

    lines: list[str] = []
    lines.append(f"# Recon Report — `{target}`\n")
    lines.append(f"_Generated: {now}_\n")
    scope_line = scope_summary(results)
    if scope_line:
        lines.append(f"_{scope_line}_\n")

    errors = results.get("errors") or []
    if errors:
        lines.append(f"## ⚠ Source errors ({len(errors)})\n")
        lines.append("_Counts below may be incomplete — these sources failed:_\n")
        lines.extend(f"- {e}" for e in errors)
        lines.append("")

    subdomains = results.get("subdomains", [])
    lines.append(f"## Subdomains ({len(subdomains)})\n")
    if subdomains:
        lines.extend(f"- `{s}`" for s in subdomains)
    else:
        lines.append("_none_")
    lines.append("")

    alive = results.get("alive", [])
    lines.append(f"## Live hosts ({len(alive)})\n")
    if alive:
        lines.append("| URL | Status | Server | Title | CORS Origin | Tech |")
        lines.append("|-----|-------:|--------|-------|-------------|------|")
        for h in alive:
            lines.append(
                "| {url} | {status} | {server} | {title} | {acao} | {tech} |".format(
                    url=h.get("url", ""),
                    status=h.get("status", ""),
                    server=(h.get("server") or "")[:40],
                    title=(h.get("title") or "")[:60].replace("|", "\\|"),
                    acao=h.get("cors_acao") or "",
                    tech=", ".join(h.get("technologies") or []),
                )
            )
    else:
        lines.append("_none_")
    lines.append("")

    urls = results.get("urls", [])
    lines.append(f"## Historical URLs ({len(urls)})\n")
    if urls:
        lines.append(f"_Showing first 50 of {len(urls)}_")
        lines.extend(f"- `{u}`" for u in urls[:50])
    else:
        lines.append("_none_")
    lines.append("")

    secrets = results.get("secrets", [])
    lines.append(f"## Potential secrets ({len(secrets)})\n")
    if secrets:
        lines.append("| Source | Pattern | Match |")
        lines.append("|--------|---------|-------|")
        for s in secrets:
            lines.append(
                "| {url} | {pat} | `{m}` |".format(
                    url=s.get("url", ""),
                    pat=s.get("pattern", ""),
                    m=(s.get("match") or "")[:80],
                )
            )
    else:
        lines.append("_none_")
    lines.append("")

    findings = results.get("header_findings", [])
    lines.append(f"## Security headers ({len(findings)})\n")
    if findings:
        lines.append("| Severity | Host | Check | Detail |")
        lines.append("|----------|------|-------|--------|")
        for f in sorted(findings, key=finding_sort_key):
            lines.append(
                "| {sev} | {host} | {check} | {detail} |".format(
                    sev=f.get("severity", ""),
                    host=f.get("host", ""),
                    check=f.get("check", ""),
                    detail=(f.get("detail") or "").replace("|", "\\|"),
                )
            )
    else:
        lines.append("_none_")

    path.write_text("\n".join(lines) + "\n")
