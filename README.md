# Cyber Recon — passive recon orchestrator for VDP/bug bounty targets

Modular Python recon toolkit for authorized security testing. Built for VDP
and bug bounty programs where passive observation is the baseline.

## Features

- **Subdomain enumeration** — passive (crt.sh + HackerTarget)
- **HTTP probing** — DNS resolve, status, server header, title, tech fingerprint
- **CORS reflection probe** (opt-in, `--active`) — sends random Origin header, detects arbitrary Origin reflection
- **Wayback mining** — historical URL discovery from Wayback CDX
- **Secret scanner** — regex detection of AWS, GitHub, Slack, Google, Stripe, JWT, generic API keys in JS files
- **Reports** — Markdown, JSON, and dark-themed HTML with sortable tables and severity color-coding
- **Async** — all modules use `aiohttp` for concurrency

## Install

```bash
cd ~/cyber-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio  # for tests
```

## Usage

Passive (default — subdomain enum, HTTP probe, Wayback, secret scan):
```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example
```

Active (adds CORS reflection probe — only with permission):
```bash
PYTHONPATH=src python3 -m recon.cli --target example.com --output output/example --active
```

Skip specific modules:
```bash
python3 -m recon.cli --target example.com --output output/example \
  --no-wayback --no-secrets
```

Output:
```
output/example/
├── results.json   # full structured data
├── report.md      # markdown summary
└── report.html    # dark-theme interactive report
```

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```

## CI

GitHub Actions runs pytest on Python 3.11 & 3.12 for every push and PR.

## Module map

```
src/recon/
├── cli.py                    # entry point + orchestration
├── modules/
│   ├── subdomains.py         # crt.sh + HackerTarget
│   ├── http_probe.py         # DNS + HTTP probe + tech fingerprint
│   ├── cors.py               # Origin reflection test
│   ├── wayback.py            # CDX endpoint discovery
│   └── secrets.py            # regex secret scanner
└── reporting/
    ├── markdown.py           # markdown writer
    └── html_report.py        # dark-theme HTML writer
```

## Disclaimer

This tool is for authorized security testing only. The `--active` flag
enables CORS reflection probing which issues HTTP requests with custom
Origin headers; use only on targets where you have explicit written
permission. See SECURITY.md for full policy.
