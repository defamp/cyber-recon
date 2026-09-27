"""HTML report writer — dark theme, single-file, no JS dependencies."""
import html
from datetime import datetime, timezone
from pathlib import Path


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
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
h1 {{ margin: 0 0 4px 0; font-size: 28px; }}
h2 {{ margin: 32px 0 12px 0; font-size: 20px; padding-bottom: 6px;
      border-bottom: 1px solid var(--border); color: var(--accent); }}
h3 {{ margin: 18px 0 8px 0; font-size: 16px; }}
.meta {{ color: var(--muted); font-size: 13px; }}
.section-count {{ color: var(--muted); font-weight: normal; font-size: 14px; }}
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
                 padding: 2px 4px; border-radius: 3px; }}
.url-list {{ max-height: 400px; overflow-y: auto;
             background: var(--surface); border: 1px solid var(--border);
             border-radius: 6px; padding: 8px 12px; font-size: 12px; }}
.url-list li {{ word-break: break-all; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
          font-size: 13px; vertical-align: top; }}
th {{ color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
tr:hover {{ background: rgba(88,166,255,0.05); }}
.empty {{ color: var(--muted); font-style: italic; }}
footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
          color: var(--muted); font-size: 12px; text-align: center; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px; margin-bottom: 24px; }}
.stat {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: 6px; padding: 12px 16px; }}
.stat-num {{ font-size: 24px; font-weight: 700; color: var(--accent); }}
.stat-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Recon Report — <span style="color:var(--accent)">{target}</span></h1>
  <div class="meta">Generated {timestamp} &middot; cyber-recon v0.1.0 &middot; passive only</div>
</header>

<section class="summary">
  <div class="stat"><div class="stat-num">{n_subs}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat"><div class="stat-num">{n_alive}</div><div class="stat-label">Live hosts</div></div>
  <div class="stat"><div class="stat-num">{n_urls}</div><div class="stat-label">Historical URLs</div></div>
  <div class="stat"><div class="stat-num" style="color:{secrets_color}">{n_secrets}</div><div class="stat-label">Potential secrets</div></div>
  <div class="stat"><div class="stat-num" style="color:{cors_color}">{n_cors_issues}</div><div class="stat-label">CORS issues</div></div>
</section>

<h2>Live hosts <span class="section-count">({n_alive})</span></h2>
{hosts_html}

<h2>Subdomains <span class="section-count">({n_subs})</span></h2>
{subs_html}

<h2>CORS analysis <span class="section-count">({n_cors_issues} issues)</span></h2>
{cors_html}

<h2>Historical URLs <span class="section-count">({n_urls})</span></h2>
{urls_html}

<h2>Potential secrets <span class="section-count">({n_secrets})</span></h2>
{secrets_html}

<footer>
  Generated by <a href="https://github.com/defamp/cyber-recon" style="color:var(--accent)">cyber-recon</a>
  &middot; passive reconnaissance only &middot; for authorized testing
</footer>
</div>
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


def _render_hosts(hosts: list[dict]) -> str:
    if not hosts:
        return '<p class="empty">No live hosts discovered.</p>'
    rows = []
    for h in hosts:
        status_cls = _classify_status(h.get("status", 0))
        techs = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in (h.get("technologies") or []))
        cors = h.get("cors_acao") or ""
        cors_html = (
            f'<span class="cors-bad">⚠ {html.escape(cors)}</span>' if cors in ("*", "null") or cors
            else '<span class="cors-ok">none</span>'
        )
        title = html.escape((h.get("title") or "")[:80])
        server = html.escape((h.get("server") or "")[:40])
        rows.append(
            f'<div class="card">'
            f'<div class="card-host">'
            f'  <a class="host-url" href="{html.escape(h.get("url",""))}" target="_blank" rel="noopener">{html.escape(h.get("url",""))}</a>'
            f'  <span class="host-status {status_cls}">{h.get("status","?")}</span>'
            f'</div>'
            f'<div style="margin-top:6px"><strong>Server:</strong> {server or "&mdash;"} &nbsp; <strong>Title:</strong> {title or "&mdash;"}</div>'
            f'<div style="margin-top:6px"><strong>CORS ACAO:</strong> {cors_html} &nbsp; {techs}</div>'
            f'</div>'
        )
    return "\n".join(rows)


def _render_subs(subs: list[str]) -> str:
    if not subs:
        return '<p class="empty">No subdomains discovered.</p>'
    return '<div class="card">' + "<br>".join(html.escape(s) for s in subs) + "</div>"


def _render_cors(hosts: list[dict]) -> str:
    issues = []
    for h in hosts:
        acao = (h.get("cors_acao") or "").strip()
        acac = (h.get("cors_acac") or "").strip().lower()
        if not acao:
            continue
        severity = "ok"
        notes = []
        if acao == "*":
            if acac == "true":
                severity = "critical"
                notes.append("Wildcard origin with credentials=true (browser will block but misconfig present).")
            else:
                severity = "high"
                notes.append("Wildcard Access-Control-Allow-Origin.")
        elif acao == "null":
            severity = "critical"
            notes.append("Reflects 'null' origin — exploitable via sandboxed iframe.")
        else:
            # reflect test — done in cli module; if reflection happens it's bad
            for tag in ("reflective_test",):
                pass
        if severity != "ok":
            issues.append((severity, h.get("host", ""), h.get("url", ""), acao, acac, " ".join(notes)))
    if not issues:
        return '<p class="empty">No obvious CORS misconfigurations detected by passive inspection.</p>'
    rows = ["<table><thead><tr><th>Severity</th><th>Host</th><th>ACAO</th><th>ACAC</th><th>Notes</th></tr></thead><tbody>"]
    for sev, host, url, acao, acac, note in issues:
        color = {"critical": "var(--red)", "high": "var(--orange)"}.get(sev, "var(--yellow)")
        rows.append(
            f'<tr><td style="color:{color};font-weight:600">{sev.upper()}</td>'
            f'<td><a class="host-url" href="{html.escape(url)}" target="_blank">{html.escape(host)}</a></td>'
            f'<td>{html.escape(acao)}</td><td>{html.escape(acac)}</td><td>{html.escape(note)}</td></tr>'
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_urls(urls: list[str]) -> str:
    if not urls:
        return '<p class="empty">No historical URLs discovered.</p>'
    shown = urls[:500]
    more = len(urls) - len(shown)
    items = "".join(f"<li>{html.escape(u)}</li>" for u in shown)
    more_html = f'<p class="meta">… and {more} more (truncated for display; full list in results.json)</p>' if more > 0 else ""
    return f'<div class="url-list"><ol>{items}</ol></div>{more_html}'


def _render_secrets(secrets: list[dict]) -> str:
    if not secrets:
        return '<p class="empty">No potential secrets detected in JS files.</p>'
    rows = ["<table><thead><tr><th>Pattern</th><th>Source URL</th><th>Match</th></tr></thead><tbody>"]
    for s in secrets:
        match = html.escape((s.get("match") or "")[:100])
        url = html.escape(s.get("url", ""))
        rows.append(
            f'<tr class="secret-row"><td>{html.escape(s.get("pattern",""))}</td>'
            f'<td><a class="host-url" href="{url}" target="_blank">{url[:80]}{"…" if len(url) > 80 else ""}</a></td>'
            f'<td><code class="secret-match">{match}</code></td></tr>'
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def write_html_report(results: dict, path: Path) -> None:
    target = results.get("target", "?")
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    hosts = results.get("alive", [])
    subs = results.get("subdomains", [])
    urls = results.get("urls", [])
    secrets = results.get("secrets", [])

    # CORS issue count
    n_cors = 0
    for h in hosts:
        acao = (h.get("cors_acao") or "").strip()
        if not acao:
            continue
        if acao in ("*", "null") or (
            results.get("cors_reflective", {}).get(h.get("host", ""), False)
        ):
            n_cors += 1

    n_secrets = len(secrets)
    secrets_color = "var(--red)" if n_secrets > 0 else "var(--green)"
    cors_color = "var(--red)" if n_cors > 0 else "var(--green)"

    html_out = HTML_TEMPLATE.format(
        target=html.escape(target),
        timestamp=timestamp,
        n_subs=len(subs),
        n_alive=len(hosts),
        n_urls=len(urls),
        n_secrets=n_secrets,
        n_cors_issues=n_cors,
        secrets_color=secrets_color,
        cors_color=cors_color,
        hosts_html=_render_hosts(hosts),
        subs_html=_render_subs(subs),
        cors_html=_render_cors(hosts),
        urls_html=_render_urls(urls),
        secrets_html=_render_secrets(secrets),
    )
    path.write_text(html_out)
