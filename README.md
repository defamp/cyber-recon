# Cyber Recon

> Passive recon orchestrator for VDP & bug bounty programs. Async, modular, ethics-first.

[![CI](https://github.com/defamp/cyber-recon/actions/workflows/tests.yml/badge.svg)](https://github.com/defamp/cyber-recon/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What it does

Single CLI that runs a coordinated recon sweep against a target domain, with
**passive-only defaults** so it's safe to run on public-scope VDP programs.

| Module | What it finds | Active? |
|---|---|---|
| Subdomain enum | crt.sh, HackerTarget, CertSpotter, AlienVault OTX, urlscan.io + hosts seen in Wayback URLs | passive |
| HTTP probe | DNS resolve, status, server, title, tech fingerprint | passive |
| Security headers | HSTS, CSP (unsafe-inline/eval, wildcard), clickjacking, nosniff, Referrer-Policy, version disclosure, cookie flags — from headers already fetched by the probe | passive (`--no-headers` to skip) |
| CORS reflection | Sends random Origin header, detects arbitrary reflection | opt-in `--active` |
| Wayback mining | Historical URLs from Wayback CDX | passive |
| Secret scanner | Regex: AWS, GitHub, Slack, Google, Stripe, JWT, generic API keys in JS files | passive |
| Nuclei integration | Runs nuclei binary, parses JSON output | opt-in `--nuclei` |
| CVE enrichment | Looks up CVE-tagged Nuclei findings against GitHub Advisory DB | opt-in `--enrich-cve` |
| Plugins | Auto-loaded bundled + user-supplied transformers | optional |

## Install

```bash
git clone https://github.com/defamp/cyber-recon.git
cd cyber-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional: nuclei binary for vulnerability scanning
# https://github.com/projectdiscovery/nuclei
```

## Usage

### Single target — passive

```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example
```

### Single target — full active scan

```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example \
  --active --nuclei --enrich-cve

# Limit nuclei to template tags (-tags) or template paths/IDs (-t)
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example \
  --nuclei --nuclei-tags cve,exposure --nuclei-templates http/cves/
```

### Scope and rate limit

Bug bounty programs define what you may touch and how fast. Give the program
scope as a file and cyber-recon will only send requests to hosts inside it:

```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example \
  --scope scope.example.txt --rate 5
```

- **Scope file**: YAML (`include:` / `exclude:` / `rate_limit:`) or plain text, one
  entry per line with `!` for exclusions — see [`scope.example.txt`](scope.example.txt).
  Entries are exact hosts, `*.wildcards` (subdomains only, not the apex) or
  `re:` regexes. Exclusions always win.
- Out-of-scope subdomains are never probed and out-of-scope Wayback URLs are
  dropped before the JS fetch; both are recorded under `out_of_scope` in
  `results.json`.
- Redirects are followed manually and **stop at the first hop that leaves
  scope**, so an SSO or third-party redirect is never requested.
- Exact hosts in the scope file that belong to the target are probed even if
  no passive source knows them.
- `--rate N` paces every request to the target (probe, CORS, JS fetch) to N/s
  and is passed to nuclei as `-rl`. Passive third-party sources (crt.sh,
  HackerTarget, Wayback) are not paced by it.
- Without `--scope`, the scope is the target domain and its subdomains — the
  same hosts as before, but redirects off that domain are no longer followed.
- In batch mode, `scope:` / `rate:` can be set per target; CLI `--scope` is the
  fallback and CLI `--rate` overrides.

### Subdomain sources

All sources are passive third-party datasets and run in parallel; one failing
source is reported under `errors` and does not stop the others. Per-source
counts are stored in `results.json` → `subdomain_sources` and shown in the
reports.

| Source | Name for `--sources` | Optional API key (env var) |
|---|---|---|
| crt.sh | `crtsh` | — |
| HackerTarget | `hackertarget` | — |
| CertSpotter (first page of issuances) | `certspotter` | `CERTSPOTTER_API_KEY` |
| AlienVault OTX passive DNS | `otx` | `OTX_API_KEY` |
| urlscan.io search (100 results) | `urlscan` | `URLSCAN_API_KEY` |

Hosts found in Wayback URLs are also added before probing (no extra request).
Pick sources with `--sources crtsh,certspotter` or `sources: [...]` per batch
target. Without keys the free quotas are small; an HTTP 429 is reported with
a hint to set one. Quotas and response formats of these third-party APIs
change over time — check each provider's current terms.

### Diff vs baseline scan

```bash
# First scan
python3 -m recon.cli --target example.com --output output/example
# Later — show delta vs prior results.json
python3 -m recon.cli --target example.com --output output/example --diff output/example/results.json
```

### Batch mode

```yaml
# batch.yml
targets:
  - domain: example.com
    output: output/example
  - domain: foo.com
    output: output/foo
    active: true
    nuclei: true
    notify:
      webhook: "slack:https://hooks.slack.com/services/T000/B000/XXX"
    skip: [wayback]
```

```bash
python3 -m recon.cli --batch batch.yml
```

### Plugins

List registered plugins:
```bash
python3 -m recon.cli --list-plugins
```

Run a specific plugin in addition to active defaults (unknown names are reported as errors):
```bash
python3 -m recon.cli --target example.com --output output/example \
  --plugin severity_counter
```

Add a custom plugin to `~/.recon/plugins/my_plugin.py`:

```python
from recon.plugins import register

async def run(target, results, **kw):
    """Compute extra stat from nuclei findings."""
    results["my_stat"] = sum(
        1 for f in results.get("nuclei", [])
        if (f.get("info") or {}).get("severity") == "critical"
    )
    return results

register("my_plugin", run, description="My custom stat", active_default=False)
```

Plugins are auto-discovered on every CLI run.

### Webhook notification

```bash
python3 -m recon.cli --target example.com --output output/example \
  --webhook "slack:https://hooks.slack.com/services/..."
# or Discord:
  --webhook "discord:https://discord.com/api/webhooks/..."
```

### Output

```
output/example/
├── results.json   # full structured data
├── report.md      # markdown summary
├── report.html    # dark-theme interactive (search + copy buttons + severity colors)
└── diff.json      # (only when --diff is used)
```

The HTML report supports:
- Global search box (filters hosts, secrets, CORS issues, URLs live)
- Copy-to-clipboard on findings, URLs, subdomains
- Click stat cards to jump to sections
- Severity color coding (critical=red, high=orange, medium=yellow)

### Security header audit

Runs automatically on every live host and adds no extra requests: it reuses the
headers from the HTTP probe (final response after redirects). Findings are
rated `low` or `info` only — most programs treat missing headers as
informative, so use them for hardening reports rather than as standalone bugs.
Hosts answering 5xx are skipped. The `header_findings` collection is included
in `--diff` output, keyed by host + check.

## Development

### Run tests
```bash
PYTHONPATH=src pytest tests/ -v
```

### Lint
```bash
ruff check src/ tests/
ruff format --check src/ tests/   # check formatting
bandit -q -r src/ -c pyproject.toml
```

### Pre-commit hooks
```bash
pip install pre-commit
pre-commit install
```

Now `git commit` runs ruff + bandit + basic file hygiene checks.

## CI/CD

- **`tests.yml`** — pytest on Python 3.11 & 3.12 for every push and PR
- **`publish.yml`** — PyPI trusted publishing via OIDC on GitHub release

To enable PyPI auto-publish, register a trusted publisher at
<https://pypi.org/manage/account/publishing/> pointing to
`defamp/cyber-recon` workflow `publish.yml`.

## Module map

```
src/recon/
├── cli.py                    # entry point + orchestration
├── batch.py                  # YAML multi-target loader
├── notify.py                 # Slack/Discord webhook payloads
├── plugins.py                # plugin registry + auto-discovery
├── diff.py                   # scan-vs-scan delta computation
├── scope.py                  # scope file parsing + host matching
├── ratelimit.py              # request pacing + scope-aware redirects
├── live_table.py             # rich live table for Nuclei findings
├── bundled_plugins/          # plugins shipped with the tool
│   └── severity.py           # (tally severities — active by default)
├── modules/
│   ├── subdomains.py         # passive sources: crt.sh, HackerTarget, CertSpotter, OTX, urlscan
│   ├── http_probe.py         # DNS + HTTP probe + tech fingerprint
│   ├── headers_audit.py      # security header + cookie flag audit
│   ├── cors.py               # Origin reflection test
│   ├── wayback.py            # CDX endpoint discovery
│   ├── secrets.py            # regex secret scanner
│   ├── nuclei.py             # nuclei wrapper
│   └── advisories.py         # GitHub CVE enrichment
└── reporting/
    ├── markdown.py           # markdown writer
    └── html_report.py        # dark-theme HTML writer (search + copy)
```

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This tool is for **authorized security testing only**. `--active` enables CORS
reflection probing (HTTP requests with custom Origin header); `--nuclei` runs
real vulnerability templates. Use only on targets where you have explicit
written permission. See [SECURITY.md](SECURITY.md) for full policy.

By using this tool you agree to:
- Respect program scope and rules-of-engagement
- Practice coordinated disclosure for any findings
- Not weaponize or redistribute scan output
