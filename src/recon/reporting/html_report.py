"""HTML report writer — dark theme, single-file, with search + copy buttons."""

import html
from datetime import UTC, datetime
from pathlib import Path

from ..modules.headers_audit import finding_sort_key
from ..modules.secrets import secret_sort_key
from .markdown import scope_summary, source_summary, top_priorities

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {target}</title>
<style>
:root {{
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  --green: #3fb950; --yellow: #d29922; --red: #f85149;
  --orange: #db6d28; --purple: #bc8cff;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.5; }}
.wrap {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 12px; }}
h1 {{ margin: 0 0 4px 0; font-size: 28px; }}
h2 {{ margin: 32px 0 12px 0; font-size: 20px; padding-bottom: 6px;
      border-bottom: 1px solid var(--border); color: var(--accent); display: flex; justify-content: space-between; align-items: center; }}
h3 {{ margin: 18px 0 8px 0; font-size: 16px; }}
.meta {{ color: var(--muted); font-size: 13px; }}
.section-count {{ color: var(--muted); font-weight: normal; font-size: 14px; }}
.search-input {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
                 padding: 6px 12px; border-radius: 6px; font-size: 13px; min-width: 240px; }}
.search-input:focus {{ outline: none; border-color: var(--accent); }}
.card {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: 6px; padding: 14px 16px; margin: 8px 0;
         font-family: ui-monospace,SFMono-Regular,Consolas,monospace; font-size: 13px; }}
.card-host {{ display: grid; grid-template-columns: 1fr auto; gap: 8px 12px; align-items: center; }}
.host-url {{ color: var(--accent); text-decoration: none; }}
.host-url:hover {{ text-decoration: underline; }}
.host-status {{ padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.s2xx {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.s3xx {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
.s4xx {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
.s5xx {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.cors-bad {{ color: var(--red); font-weight: 600; }}
.cors-ok {{ color: var(--muted); }}
.tag {{ display: inline-block; background: rgba(88,166,255,0.1);
        color: var(--accent); padding: 2px 8px; border-radius: 12px;
        font-size: 11px; margin-right: 4px; }}
.secret-row {{ color: var(--red); }}
.secret-match {{ color: var(--red); background: rgba(248,81,73,0.1);
                 padding: 2px 4px; border-radius: 3px; font-family: inherit; }}
.copy-btn {{ background: transparent; border: 1px solid var(--border); color: var(--muted);
             padding: 2px 8px; border-radius: 4px; font-size: 11px; cursor: pointer; }}
.copy-btn:hover {{ color: var(--accent); border-color: var(--accent); }}
.copy-btn.copied {{ color: var(--green); border-color: var(--green); }}
.url-list {{ max-height: 400px; overflow-y: auto;
             background: var(--surface); border: 1px solid var(--border);
             border-radius: 6px; padding: 8px 12px; font-size: 12px; }}
.url-list li {{ word-break: break-all; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
          font-size: 13px; vertical-align: top; }}
th {{ color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; position: sticky; top: 0; background: var(--surface); }}
tr:hover {{ background: rgba(88,166,255,0.05); }}
.empty {{ color: var(--muted); font-style: italic; }}
footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
          color: var(--muted); font-size: 12px; text-align: center; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px; margin-bottom: 24px; }}
.stat {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: 6px; padding: 12px 16px; cursor: pointer; transition: border-color 0.15s; }}
.stat:hover {{ border-color: var(--accent); }}
.stat-num {{ font-size: 24px; font-weight: 700; color: var(--accent); }}
.stat-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
.sev-critical {{ color: var(--red); font-weight: 600; }}
.sev-high {{ color: var(--orange); font-weight: 600; }}
.sev-medium {{ color: var(--yellow); }}
.sev-low {{ color: var(--accent); }}
.sev-info {{ color: var(--muted); }}
.nuclei-row td {{ font-size: 12px; }}
.nuclei-row .info-cell {{ color: var(--muted); font-size: 11px; max-width: 400px; word-break: break-word; }}
.hidden {{ display: none !important; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div>
    <h1>Recon Report — <span style="color:var(--accent)">{target}</span></h1>
    <div class="meta">Generated {timestamp} &middot; cyber-recon v0.1.0 &middot; {mode}{scope_html}</div>
  </div>
  <input type="search" id="globalSearch" class="search-input" placeholder="Search report (URL, host, secret, finding)…">
</header>
{errors_html}
{priority_html}
<section class="summary">
  <div class="stat" data-jump="live-hosts"><div class="stat-num">{n_alive}</div><div class="stat-label">Live hosts</div></div>
  <div class="stat" data-jump="subdomains"><div class="stat-num">{n_subs}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat" data-jump="cors"><div class="stat-num" style="color:{cors_color}">{n_cors_issues}</div><div class="stat-label">CORS issues</div></div>
  <div class="stat" data-jump="urls"><div class="stat-num">{n_urls}</div><div class="stat-label">Historical URLs</div></div>
  <div class="stat" data-jump="secrets"><div class="stat-num" style="color:{secrets_color}">{n_secrets}</div><div class="stat-label">Potential secrets</div></div>
  <div class="stat" data-jump="headers"><div class="stat-num" style="color:{headers_color}">{n_header_issues}</div><div class="stat-label">Header issues</div></div>
  <div class="stat" data-jump="tls"><div class="stat-num" style="color:{tls_color}">{n_tls_issues}</div><div class="stat-label">TLS issues</div></div>
  <div class="stat" data-jump="nuclei"><div class="stat-num" style="color:{nuclei_color}">{n_nuclei}</div><div class="stat-label">Nuclei hits</div></div>
</section>

<h2 id="live-hosts">Live hosts <span class="section-count">({n_alive})</span></h2>
{hosts_html}

<h2 id="subdomains">Subdomains <span class="section-count">({n_subs})</span></h2>
{sources_html}{subs_html}

<h2 id="cors">CORS analysis <span class="section-count">({n_cors_issues} issues)</span></h2>
{cors_html}

<h2 id="urls">Historical URLs <span class="section-count">({n_urls})</span></h2>
{urls_html}

<h2 id="secrets">Potential secrets <span class="section-count">({n_secrets})</span></h2>
{secrets_html}

<h2 id="headers">Security headers <span class="section-count">({n_headers} findings)</span></h2>
{headers_html}

<h2 id="tls">TLS certificates <span class="section-count">({n_tls} findings)</span></h2>
{tls_html}

<h2 id="nuclei">Nuclei findings <span class="section-count">({n_nuclei})</span></h2>
{nuclei_html}

<footer>
  Generated by <a href="https://github.com/defamp/cyber-recon" style="color:var(--accent)">cyber-recon</a>
  &middot; passive reconnaissance only &middot; for authorized testing
</footer>
</div>

<script>
(function() {{
  // Search filter — hides rows/list items not matching query
  const search = document.getElementById('globalSearch');
  function applyFilter() {{
    const q = (search.value || '').toLowerCase().trim();
    document.querySelectorAll('[data-searchable]').forEach(el => {{
      const hay = (el.getAttribute('data-searchable') || '').toLowerCase();
      el.classList.toggle('hidden', q && !hay.includes(q));
    }});
  }}
  search.addEventListener('input', applyFilter);

  // Stat cards jump to section
  document.querySelectorAll('.stat[data-jump]').forEach(card => {{
    card.addEventListener('click', () => {{
      const target = document.getElementById(card.getAttribute('data-jump'));
      if (target) target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }});
  }});

  // Copy-to-clipboard
  document.body.addEventListener('click', e => {{
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    const text = btn.getAttribute('data-copy') || '';
    navigator.clipboard.writeText(text).then(() => {{
      const orig = btn.textContent;
      btn.textContent = '✓ copied';
      btn.classList.add('copied');
      setTimeout(() => {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1500);
    }});
  }});
}})();
</script>
</body>
</html>
"""


def _classify_status(status: int) -> str:
    if 200 <= status < 300:
        return "s2xx"
    if 300 <= status < 400:
        return "s3xx"
    if 400 <= status < 500:
        return "s4xx"
    return "s5xx"


def _esc_attr(s: str) -> str:
    """Escape for safe embedding in an HTML attribute (data-searchable, data-copy)."""
    return html.escape(s or "", quote=True)


def _render_hosts(hosts: list[dict]) -> str:
    if not hosts:
        return '<p class="empty">No live hosts discovered.</p>'
    rows = []
    for h in hosts:
        status_cls = _classify_status(h.get("status", 0))
        techs = "".join(
            f'<span class="tag">{html.escape(t)}</span>' for t in (h.get("technologies") or [])
        )
        cors = h.get("cors_acao") or ""
        cors_html = (
            f'<span class="cors-bad">⚠ {html.escape(cors)}</span>'
            if cors
            else '<span class="cors-ok">none</span>'
        )
        title = html.escape((h.get("title") or "")[:80])
        server = html.escape((h.get("server") or "")[:40])
        url = h.get("url", "")
        host = h.get("host", "")
        searchable = f"{host} {url} {title} {server} {' '.join(h.get('technologies') or [])}"
        rows.append(
            f'<div class="card" data-searchable="{_esc_attr(searchable)}">'
            f'<div class="card-host">'
            f'  <a class="host-url" href="{html.escape(url)}" target="_blank" rel="noopener">{html.escape(url)}</a>'
            f'  <span class="host-status {status_cls}">{h.get("status", "?")}</span>'
            f"</div>"
            f'<div style="margin-top:6px"><strong>Server:</strong> {server or "&mdash;"} &nbsp; <strong>Title:</strong> {title or "&mdash;"}</div>'
            f'<div style="margin-top:6px"><strong>CORS ACAO:</strong> {cors_html} &nbsp; {techs}</div>'
            f"</div>"
        )
    return "\n".join(rows)


def _render_subs(subs: list[str]) -> str:
    if not subs:
        return '<p class="empty">No subdomains discovered.</p>'
    items = []
    for s in subs:
        items.append(
            f'<div data-searchable="{_esc_attr(s)}" '
            f'style="padding:2px 0">{html.escape(s)} '
            f'<button class="copy-btn" data-copy="{_esc_attr(s)}">copy</button></div>'
        )
    return '<div class="card">' + "".join(items) + "</div>"


def _cors_issues(hosts: list[dict], reflective: dict[str, dict]) -> list[tuple]:
    issues = []
    for h in hosts:
        acao = (h.get("cors_acao") or "").strip()
        acac = (h.get("cors_acac") or "").strip().lower()
        active = reflective.get(h.get("host", ""), {})
        if active.get("reflects"):
            # The passive probe sends no Origin, so reflection only shows up in
            # the active probe's response headers.
            acao = (active.get("acao") or acao).strip()
            acac = (active.get("acac") or acac).strip().lower()
        if not acao:
            continue
        severity = "ok"
        notes = []
        if acao == "*":
            if acac == "true":
                severity = "critical"
                notes.append("Wildcard origin with credentials=true.")
            else:
                severity = "high"
                notes.append("Wildcard Access-Control-Allow-Origin.")
        elif acao == "null":
            severity = "critical"
            notes.append("Reflects 'null' origin — exploitable via sandboxed iframe.")
        else:
            host = h.get("host", "")
            if reflective.get(host, {}).get("reflects"):
                severity = "critical"
                notes.append(
                    f"Reflects arbitrary Origin: {reflective[host].get('tested_origin', '')}"
                )
        if severity != "ok":
            issues.append(
                (severity, h.get("host", ""), h.get("url", ""), acao, acac, " ".join(notes))
            )
    return issues


def _render_cors(hosts: list[dict], reflective: dict[str, dict]) -> str:
    issues = _cors_issues(hosts, reflective)
    if not issues:
        return '<p class="empty">No obvious CORS misconfigurations detected.</p>'
    rows = [
        "<table><thead><tr><th>Severity</th><th>Host</th><th>ACAO</th><th>ACAC</th><th>Notes</th></tr></thead><tbody>"
    ]
    for sev, host, url, acao, acac, note in issues:
        color = {"critical": "var(--red)", "high": "var(--orange)"}.get(sev, "var(--yellow)")
        searchable = f"{host} {acao} {acac} {note}"
        rows.append(
            f'<tr data-searchable="{_esc_attr(searchable)}">'
            f'<td style="color:{color};font-weight:600">{sev.upper()}</td>'
            f'<td><a class="host-url" href="{html.escape(url)}" target="_blank">{html.escape(host)}</a></td>'
            f"<td>{html.escape(acao)}</td><td>{html.escape(acac)}</td><td>{html.escape(note)}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_urls(urls: list[str]) -> str:
    if not urls:
        return '<p class="empty">No historical URLs discovered.</p>'
    shown = urls[:500]
    more = len(urls) - len(shown)
    items = "".join(
        f'<li data-searchable="{_esc_attr(u)}">{html.escape(u)} '
        f'<button class="copy-btn" data-copy="{_esc_attr(u)}">copy</button></li>'
        for u in shown
    )
    more_html = (
        f'<p class="meta">… and {more} more (full list in results.json)</p>' if more > 0 else ""
    )
    return f'<div class="url-list"><ol>{items}</ol></div>{more_html}'


def _render_secrets(secrets: list[dict]) -> str:
    if not secrets:
        return '<p class="empty">No potential secrets detected in JS files.</p>'
    rows = [
        "<table><thead><tr><th>Confidence</th><th>Pattern</th><th>Source URL</th><th>Match</th><th></th></tr></thead><tbody>"
    ]
    for s in sorted(secrets, key=secret_sort_key):
        match = s.get("match") or ""
        url = s.get("url") or ""
        pattern = s.get("pattern") or ""
        confidence = s.get("confidence") or "—"
        reason = s.get("reason") or ""
        sev_cls = {"high": "sev-critical", "medium": "sev-medium", "low": "sev-low"}.get(
            confidence, "sev-info"
        )
        searchable = f"{confidence} {pattern} {url} {match} {reason}"
        rows.append(
            f'<tr class="secret-row" data-searchable="{_esc_attr(searchable)}">'
            f'<td><span class="{sev_cls}" title="{_esc_attr(reason)}">{html.escape(confidence.upper())}</span></td>'
            f"<td>{html.escape(pattern)}</td>"
            f'<td><a class="host-url" href="{html.escape(url)}" target="_blank">{html.escape(url[:80])}{"…" if len(url) > 80 else ""}</a></td>'
            f'<td><code class="secret-match">{html.escape(match[:100])}</code></td>'
            f'<td><button class="copy-btn" data-copy="{_esc_attr(match)}">copy</button></td></tr>'
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_priority(top: list[dict]) -> str:
    if not top:
        return ""
    rows = [
        '<h2 id="priority">Where to look first <span class="section-count">(heuristic)</span></h2>',
        "<table><thead><tr><th>Score</th><th>Host</th><th>Why</th></tr></thead><tbody>",
    ]
    for p in top:
        url = p.get("url") or ""
        why = "; ".join(p.get("reasons") or [])
        rows.append(
            f'<tr data-searchable="{_esc_attr(p.get("host", "") + " " + why)}">'
            f'<td style="font-weight:700;color:var(--purple)">{int(p.get("score", 0))}</td>'
            f'<td><a class="host-url" href="{html.escape(url)}" target="_blank">{html.escape(p.get("host", ""))}</a></td>'
            f'<td class="meta">{html.escape(why)}</td></tr>'
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_headers(
    findings: list[dict], empty: str = "No header findings (audit skipped or no live hosts)."
) -> str:
    if not findings:
        return f'<p class="empty">{html.escape(empty)}</p>'
    rows = [
        "<table><thead><tr><th>Severity</th><th>Host</th><th>Check</th><th>Detail</th></tr></thead><tbody>"
    ]
    for f in sorted(findings, key=finding_sort_key):
        sev = (f.get("severity") or "info").lower()
        host = f.get("host", "")
        url = f.get("url", "")
        check = f.get("check", "")
        detail = f.get("detail", "")
        searchable = f"{host} {check} {detail} {sev}"
        rows.append(
            f'<tr data-searchable="{_esc_attr(searchable)}">'
            f'<td><span class="sev-{html.escape(sev)}">{html.escape(sev.upper())}</span></td>'
            f'<td><a class="host-url" href="{html.escape(url)}" target="_blank">{html.escape(host)}</a></td>'
            f"<td><code>{html.escape(check)}</code></td>"
            f"<td>{html.escape(detail)}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_nuclei(findings: list[dict]) -> str:
    if not findings:
        return '<p class="empty">No Nuclei findings (binary missing or none detected).</p>'
    # First check for warning dict
    if len(findings) == 1 and findings[0].get("_warning"):
        return f'<p class="empty">⚠ {html.escape(findings[0]["_warning"])}</p>'
    rows = [
        "<table><thead><tr><th>Severity</th><th>Template</th><th>Name</th><th>Matched at</th><th>Info</th></tr></thead><tbody>"
    ]
    for f in findings:
        sev = (f.get("info", {}).get("severity") or "info").lower()
        template = f.get("template-id", "")
        name = f.get("info", {}).get("name", "")
        matched = f.get("matched-at", "")
        description = f.get("info", {}).get("description", "")[:200]
        searchable = f"{template} {name} {matched} {description}"
        rows.append(
            f'<tr class="nuclei-row" data-searchable="{_esc_attr(searchable)}">'
            f'<td><span class="sev-{sev}">{html.escape(sev.upper())}</span></td>'
            f"<td><code>{html.escape(template)}</code></td>"
            f"<td>{html.escape(name)}</td>"
            f'<td><a class="host-url" href="{html.escape(matched)}" target="_blank">{html.escape(matched[:60])}</a></td>'
            f'<td class="info-cell">{html.escape(description)}</td></tr>'
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_errors(errors: list[str]) -> str:
    if not errors:
        return ""
    items = "".join(f"<li>{html.escape(str(e))}</li>" for e in errors)
    return (
        '<section class="errors" style="border:1px solid var(--red);border-radius:8px;'
        'padding:8px 16px;margin:16px 0">'
        f'<strong style="color:var(--red)">&#9888; {len(errors)} source error(s)</strong> '
        "&mdash; counts below may be incomplete."
        f"<ul>{items}</ul></section>"
    )


def write_html_report(results: dict, path: Path) -> None:
    target = results.get("target", "?")
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    hosts = results.get("alive", [])
    subs = results.get("subdomains", [])
    urls = results.get("urls", [])
    secrets = results.get("secrets", [])
    nuclei = results.get("nuclei", [])
    reflective = results.get("cors_reflective", {})
    header_findings = results.get("header_findings", [])
    # Info-level findings (missing Referrer-Policy etc.) would drown the stat card
    n_header_issues = sum(1 for f in header_findings if f.get("severity") != "info")
    headers_color = "var(--yellow)" if n_header_issues > 0 else "var(--green)"
    tls_findings = results.get("tls_findings") or []
    n_tls_issues = sum(1 for f in tls_findings if f.get("severity") != "info")
    tls_color = "var(--yellow)" if n_tls_issues > 0 else "var(--green)"

    n_cors = len(_cors_issues(hosts, reflective))

    n_secrets = len(secrets)
    n_nuclei = len([f for f in nuclei if not f.get("_warning")])
    secrets_color = "var(--red)" if n_secrets > 0 else "var(--green)"
    cors_color = "var(--red)" if n_cors > 0 else "var(--green)"
    if n_nuclei > 0:
        nuclei_color = (
            "var(--orange)"
            if any(
                (f.get("info", {}).get("severity") or "").lower() in ("critical", "high")
                for f in nuclei
                if not f.get("_warning")
            )
            else "var(--yellow)"
        )
    else:
        nuclei_color = "var(--green)"

    html_out = HTML_TEMPLATE.format(
        target=html.escape(target),
        timestamp=timestamp,
        n_subs=len(subs),
        n_alive=len(hosts),
        n_urls=len(urls),
        n_secrets=n_secrets,
        n_cors_issues=n_cors,
        n_nuclei=n_nuclei,
        secrets_color=secrets_color,
        cors_color=cors_color,
        nuclei_color=nuclei_color,
        hosts_html=_render_hosts(hosts),
        subs_html=_render_subs(subs),
        cors_html=_render_cors(hosts, reflective),
        urls_html=_render_urls(urls),
        secrets_html=_render_secrets(secrets),
        nuclei_html=_render_nuclei(nuclei),
        n_headers=len(header_findings),
        n_header_issues=n_header_issues,
        headers_color=headers_color,
        headers_html=_render_headers(header_findings),
        n_tls=len(tls_findings),
        n_tls_issues=n_tls_issues,
        tls_color=tls_color,
        tls_html=_render_headers(
            tls_findings, empty="No TLS findings (check skipped, no HTTPS hosts, or all valid)."
        ),
        priority_html=_render_priority(top_priorities(results)),
        errors_html=_render_errors(results.get("errors") or []),
        mode="active modules enabled" if results.get("active") else "passive only",
        sources_html=(
            f'<p class="meta">Per source: {html.escape(source_summary(results))}</p>'
            if source_summary(results)
            else ""
        ),
        scope_html=(
            f" &middot; {html.escape(scope_summary(results))}" if scope_summary(results) else ""
        ),
    )
    path.write_text(html_out)
