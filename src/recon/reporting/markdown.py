"""Markdown report writer."""

from datetime import UTC, datetime
from pathlib import Path

from ..modules.nuclei import finding_name


def write_markdown_report(results: dict, path: Path) -> None:
    target = results.get("target", "?")
    now = datetime.now(UTC).isoformat(timespec="seconds")

    lines: list[str] = []
    lines.append(f"# Recon Report — `{target}`\n")
    lines.append(f"_Generated: {now}_\n")

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

    findings = [f for f in results.get("nuclei", []) or [] if not f.get("_warning")]
    lines.append(f"## Nuclei findings ({len(findings)})\n")
    if findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(
            findings,
            key=lambda f: order.get(((f.get("info") or {}).get("severity") or "info").lower(), 5),
        )
        lines.append("| Severity | Template | Name | Matched at |")
        lines.append("|----------|----------|------|------------|")
        for f in findings:
            lines.append(
                "| {sev} | {tid} | {name} | {at} |".format(
                    sev=((f.get("info") or {}).get("severity") or "info").lower(),
                    tid=f.get("template-id", ""),
                    name=finding_name(f).replace("|", "\\|"),
                    at=f.get("matched-at", ""),
                )
            )
    else:
        lines.append("_none_")
    lines.append("")

    secrets = results.get("secrets", [])
    lines.append(f"## Potential secrets ({len(secrets)})\n")
    if secrets:
        lines.append("| Confidence | Pattern | Match | Seen in |")
        lines.append("|------------|---------|-------|---------|")
        for s in secrets:
            n = s.get("occurrences", 1)
            seen = s.get("url", "") + (f" (+{n - 1} more)" if n > 1 else "")
            lines.append(
                "| {conf} | {pat} | `{m}` | {seen} |".format(
                    conf=s.get("confidence", ""),
                    pat=s.get("pattern", ""),
                    m=(s.get("match") or "")[:80].replace("|", "\\|"),
                    seen=seen,
                )
            )
    else:
        lines.append("_none_")

    path.write_text("\n".join(lines) + "\n")
