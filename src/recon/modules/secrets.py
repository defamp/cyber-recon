"""Scan JS files for hardcoded secrets — passive regex check plus triage.

Every regex hit is classified before it is reported:

- placeholders and documentation examples are dropped
- generic ``api_key = "..."`` hits need a random-looking value (entropy,
  letters + digits), otherwise they are dropped
- JWTs must decode to a JSON header with ``alg``
- the rest get a confidence (high / medium / low) and a short reason
"""

import asyncio
import base64
import binascii
import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import aiohttp

from ..ratelimit import RateLimiter, scoped_get
from ..scope import Scope

CONCURRENCY = 20
TIMEOUT = 10
JS_FETCH_LIMIT = 200  # don't try to fetch every JS, cap at this


PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(?i)aws[_\\-]?secret[_\\-]?(?:access[_\\-]?)?key.{0,40}?[\"']([A-Za-z0-9/+=]{40})[\"']",
    "github_pat": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack_token": r"xox[abpr]-[0-9A-Za-z-]{10,48}",
    "google_api": r"AIza[0-9A-Za-z_-]{35}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "stripe_key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "generic_api_key": r"(?i)(?:api[_-]?key|apikey|secret)[\"' :=]{1,5}[\"']([A-Za-z0-9_-]{16,64})[\"']",
    "github_fine_grained": r"github_pat_[A-Za-z0-9_]{50,}",
    "gitlab_pat": r"glpat-[A-Za-z0-9_-]{20,}",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "sendgrid_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
}

# Provider formats distinctive enough that a hit is very likely real.
HIGH_SIGNAL = {
    "aws_access_key",
    "github_pat",
    "github_fine_grained",
    "gitlab_pat",
    "npm_token",
    "slack_token",
    "slack_webhook",
    "sendgrid_key",
    "private_key",
}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
PLACEHOLDER_WORDS = (
    "example",
    "xxxx",
    "your_",
    "your-",
    "yourkey",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "redacted",
    "insert",
)
GENERIC_MIN_ENTROPY = 3.5  # bits/char; random base62 keys sit well above 4


@dataclass
class Finding:
    url: str
    pattern: str
    match: str
    confidence: str = "medium"
    reason: str = ""


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    return re.search(r"(.)\1{5,}", value) is not None  # aaaaaa, 000000


def _jwt_header(token: str) -> dict | None:
    head = token.split(".", 1)[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        data = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    return data if isinstance(data, dict) and "alg" in data else None


def classify(pattern: str, match: str, value: str | None = None) -> tuple[str, str] | None:
    """Return (confidence, reason) for a regex hit, or None to drop it.

    ``value`` is the secret part of the match when the regex captures it
    (generic keys, AWS secrets); defaults to the whole match.
    """
    value = value or match
    if _is_placeholder(value):
        return None
    if pattern == "stripe_key":
        if match.startswith("sk_test_"):
            return "low", "Stripe test-mode key"
        return "high", "Stripe live secret key"
    if pattern in HIGH_SIGNAL:
        return "high", "provider-specific key format"
    if pattern == "aws_secret":
        if shannon_entropy(value) < GENERIC_MIN_ENTROPY:
            return None
        return "high", "AWS secret access key next to its variable name"
    if pattern == "google_api":
        return "medium", "Google API keys are often public by design; check key restrictions"
    if pattern == "jwt":
        header = _jwt_header(match)
        if header is None:
            return None
        return "low", f"JWT (alg={header.get('alg')}); often a public/anon token — check claims"
    if pattern == "generic_api_key":
        has_digit = any(c.isdigit() for c in value)
        has_alpha = any(c.isalpha() for c in value)
        # camelCase identifiers and words ("passwordResetField") have no digits
        # and lower entropy than real keys
        if not (has_digit and has_alpha) or shannon_entropy(value) < GENERIC_MIN_ENTROPY:
            return None
        return "medium", "high-entropy value assigned to a key/secret variable"
    return "medium", ""


def find_secrets(url: str, body: str) -> list[Finding]:
    """Regex + classify one file's contents; one finding per distinct match."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for name, pat in PATTERNS.items():
        for m in re.finditer(pat, body):
            match = m.group(0)[:120]
            if (name, match) in seen:
                continue
            seen.add((name, match))
            value = m.group(1) if m.re.groups else None
            verdict = classify(name, m.group(0), value)
            if verdict is None:
                continue
            confidence, reason = verdict
            findings.append(Finding(url, name, match, confidence, reason))
    return findings


def filter_by_confidence(findings: list[dict], minimum: str) -> list[dict]:
    limit = CONFIDENCE_ORDER[minimum]
    return [f for f in findings if CONFIDENCE_ORDER.get(f.get("confidence", "medium"), 1) <= limit]


def secret_sort_key(f: dict) -> tuple:
    return (CONFIDENCE_ORDER.get(f.get("confidence", "medium"), 1), f.get("pattern", ""))


def _filter_js_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        try:
            path = urlparse(u).path.lower()
        except Exception:
            continue
        if path.endswith((".js", ".mjs", ".cjs")) and not path.endswith((".min.js.map",)):
            out.append(u)
            if len(out) >= JS_FETCH_LIMIT:
                break
    return out


async def _scan_url(
    session: aiohttp.ClientSession,
    url: str,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
) -> list[Finding]:
    try:
        async with scoped_get(
            session,
            url,
            scope=scope,
            limiter=limiter,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as (r, _):
            if r.status >= 300:  # error, or a redirect we declined to follow
                return []
            body = await r.text(errors="ignore")
    except Exception:
        return []
    return find_secrets(url, body)


async def scan_secrets(
    urls: list[str],
    *,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
) -> list[dict]:
    js_urls = _filter_js_urls(urls)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(u: str) -> list[Finding]:
        async with sem:
            return await _scan_url(session, u, scope, limiter)

    headers = {"User-Agent": "cyber-recon/0.1 (+passive)"}
    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        results = await asyncio.gather(*(bounded(u) for u in js_urls))
    flat = [asdict(f) for sub in results for f in sub]
    return sorted(flat, key=secret_sort_key)
