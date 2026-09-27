# Cyber Recon — passive recon orchestrator for VDP/bug bounty targets

## Features
- Subdomain enumeration (passive: crt.sh, HackerTarget, ThreatCrowd fallback)
- HTTP probing & tech fingerprinting (server, headers, CORS misconfig)
- URL/JS endpoint mining from Wayback Machine & Common Crawl
- Secret/API key detection in JS files (regex-based)
- Markdown + JSON report per target

## Install
```bash
cd ~/cyber-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python -m recon --target example.com --output output/example
```

Only use against targets you have explicit written permission to test.

## Disclaimer
This tool is for authorized security testing only. Passive reconnaissance only
by default. Active scanning modules require explicit opt-in flags.
