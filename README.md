# Cyber Recon — passive recon orchestrator for VDP/bug bounty targets

Modular Python recon toolkit for authorized security testing. Built for VDP
and bug bounty programs where passive observation is the baseline.

## Features

- **Subdomain enumeration** — passive (crt.sh + HackerTarget)
- **HTTP probing** — DNS resolve, status, server header, title, tech fingerprint
- **CORS reflection probe** (opt-in, `--active`) — sends random Origin, detects arbitrary reflection
- **Wayback mining** — historical URL discovery from Wayback CDX
- **Secret scanner** — regex detection of AWS, GitHub, Slack, Google, Stripe, JWT, generic API keys
- **Nuclei integration** (opt-in, `--nuclei`) — invokes nuclei binary, parses JSON output
- **Multi-target batch mode** (`--batch`) — YAML config with per-target overrides
- **Webhook notifier** (`--webhook`) — Slack or Discord summary post
- **Reports** — Markdown, JSON, and dark-themed HTML with live search & copy buttons
- **Async** — all modules use `aiohttp` for concurrency

## Install

```bash
cd ~/cyber-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio  # for tests

# Optional: install nuclei binary from https://github.com/projectdiscovery/nuclei
# Only required if you use --nuclei flag.
```

## Usage

### Single target — passive

```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example
```

### Single target — active (CORS reflection probe + Nuclei)

```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example --active --nuclei
```

### Batch mode

Create `batch.yml`:
```yaml
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

Run:
```bash
python3 -m recon.cli --batch batch.yml
```

### Webhook notification

```bash
python3 -m recon.cli --target example.com --output output/example --webhook "slack:https://hooks.slack.com/..."
# or
python3 -m recon.cli --target example.com --output output/example --webhook "discord:https://discord.com/api/webhooks/..."
```

### Skip modules

```bash
python3 -m recon.cli --target example.com --output output/example \
  --no-wayback --no-secrets --no-html
```

### Output

```
output/example/
├── results.json   # full structured data
├── report.md      # markdown summary
└── report.html    # dark-theme interactive report (search + copy buttons)
```

The HTML report supports:
- Global search box (filters hosts, secrets, CORS issues, URLs live)
- Copy-to-clipboard on findings, URLs, subdomains
- Click stat cards to jump to sections
- Severity color coding (critical=red, high=orange, medium=yellow)

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```

## CI

GitHub Actions runs pytest on Python 3.11 & 3.12 for every push and PR.
The `publish.yml` workflow uses PyPI trusted publishing (OIDC) to publish
the package automatically when a GitHub release is created.

To enable PyPI publishing:
1. Visit https://pypi.org/manage/account/publishing/
2. Add a trusted publisher pointing to `defamp/cyber-recon` workflow `publish.yml`

## Module map

```
src/recon/
├── cli.py                    # entry point + orchestration
├── batch.py                  # YAML multi-target loader
├── notify.py                 # Slack/Discord webhook payloads
├── modules/
│   ├── subdomains.py         # crt.sh + HackerTarget
│   ├── http_probe.py         # DNS + HTTP probe + tech fingerprint
│   ├── cors.py               # Origin reflection test
│   ├── wayback.py            # CDX endpoint discovery
│   ├── secrets.py            # regex secret scanner
│   └── nuclei.py             # nuclei wrapper
└── reporting/
    ├── markdown.py           # markdown writer
    └── html_report.py        # dark-theme HTML writer (search + copy)
```

## Disclaimer

This tool is for authorized security testing only. `--active` enables CORS
reflection probing (HTTP requests with custom Origin header); `--nuclei`
runs real vulnerability templates. Use only on targets where you have
explicit written permission. See SECURITY.md for full policy.
