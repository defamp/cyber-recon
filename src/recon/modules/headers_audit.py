"""Security header audit — passive, works on headers already captured by the HTTP probe.

No extra requests are made. Severities are deliberately conservative: most
programs rate missing headers as informative, so nothing here goes above
"medium" on its own.
"""

import re
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

HSTS_MIN_MAX_AGE = 15552000  # 180 days, the common baseline for HSTS preload/best practice
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class HeaderFinding:
    host: str
    url: str
    check: str
    severity: str
    detail: str


def _csp_directives(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            # First occurrence wins, as in browsers
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _check_hsts(value: str | None, is_https: bool) -> list[tuple[str, str, str]]:
    if not is_https:
        return []
    if not value:
        return [("hsts-missing", "low", "No Strict-Transport-Security header on HTTPS response.")]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if not m:
        return [("hsts-invalid", "low", f"HSTS header without max-age: {value[:80]}")]
    age = int(m.group(1))
    if age < HSTS_MIN_MAX_AGE:
        return [("hsts-short-max-age", "info", f"HSTS max-age={age} (< {HSTS_MIN_MAX_AGE}).")]
    return []


def _check_csp(value: str | None) -> list[tuple[str, str, str]]:
    if not value:
        return [("csp-missing", "low", "No Content-Security-Policy header.")]
    directives = _csp_directives(value)
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        return [("csp-no-script-src", "low", "CSP sets neither script-src nor default-src.")]
    out = []
    if "'unsafe-inline'" in script and not any(
        t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script
    ):
        # A nonce or hash makes browsers ignore 'unsafe-inline' (CSP level 2+)
        out.append(("csp-unsafe-inline", "low", "Script policy allows 'unsafe-inline'."))
    if "'unsafe-eval'" in script:
        out.append(("csp-unsafe-eval", "info", "Script policy allows 'unsafe-eval'."))
    if "*" in script or "data:" in script:
        out.append(("csp-wildcard-script", "low", "Script policy allows '*' or data: sources."))
    return out


def _check_framing(xfo: str | None, csp: str | None) -> list[tuple[str, str, str]]:
    if xfo and xfo.strip().lower() in ("deny", "sameorigin"):
        return []
    if csp and "frame-ancestors" in _csp_directives(csp):
        return []
    return [
        (
            "clickjacking",
            "low",
            "Neither X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is set.",
        )
    ]


def _check_misc(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    out = []
    if (headers.get("x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(("nosniff-missing", "info", "X-Content-Type-Options: nosniff not set."))
    if not headers.get("referrer-policy"):
        out.append(("referrer-policy-missing", "info", "No Referrer-Policy header."))
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(name) or ""
        if VERSION_RE.search(value):
            out.append(("version-disclosure", "info", f"{name}: {value[:80]}"))
    return out


def _check_cookies(cookies: list[str], is_https: bool) -> list[tuple[str, str, str]]:
    out = []
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            # Only a missing Secure flag on HTTPS is worth more than info: HttpOnly
            # is legitimately absent on cookies that JS must read.
            sev = "low" if "Secure" in missing else "info"
            out.append(("cookie-flags", sev, f"Cookie {name!r} missing {', '.join(missing)}."))
    return out


def finding_sort_key(f: dict) -> tuple:
    """Most severe first, then by host and check — used by the report writers."""
    return (SEVERITY_ORDER.get(f.get("severity", "info"), 5), f.get("host", ""), f.get("check", ""))


def audit_host(host: dict) -> list[dict]:
    """Audit one probed host dict (as produced by http_probe.probe_targets)."""
    url = host.get("url") or ""
    status = host.get("status") or 0
    if not url or status >= 500:
        return []
    headers = {k.lower(): v for k, v in (host.get("security_headers") or {}).items()}
    is_https = urlparse(url).scheme == "https"
    checks = (
        _check_hsts(headers.get("strict-transport-security"), is_https)
        + _check_csp(headers.get("content-security-policy"))
        + _check_framing(headers.get("x-frame-options"), headers.get("content-security-policy"))
        + _check_misc(headers)
        + _check_cookies(host.get("set_cookies") or [], is_https)
    )
    return [
        asdict(
            HeaderFinding(
                host=host.get("host", ""), url=url, check=check, severity=sev, detail=detail
            )
        )
        for check, sev, detail in checks
    ]


def audit_headers(hosts: list[dict]) -> list[dict]:
    """Audit every live host. Returns a flat list of finding dicts."""
    return [f for h in hosts for f in audit_host(h)]
