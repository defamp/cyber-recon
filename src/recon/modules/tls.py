"""TLS certificate check — one verified handshake per HTTPS host (stdlib ssl only).

The handshake verifies the certificate like a browser would. When verification
fails, OpenSSL's reason (expired, self-signed, hostname mismatch, …) becomes the
finding; when it succeeds, expiry and protocol are recorded.

With ``legacy=True`` (only under --active) one extra handshake per host checks
whether TLS 1.0/1.1 is still accepted. Whether that can be tested at all
depends on the local OpenSSL build; if the client itself refuses, the result
is reported as untestable rather than as "not accepted".
"""

from __future__ import annotations

import asyncio
import ssl
import warnings
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from ..ratelimit import RateLimiter

CONCURRENCY = 20
TIMEOUT = 8
EXPIRY_WARN_DAYS = 14


@dataclass
class TlsFinding:
    host: str
    url: str
    check: str
    severity: str
    detail: str


def _classify_verify_error(message: str) -> tuple[str, str]:
    msg = message.lower()
    if "expired" in msg:
        return "cert-expired", "medium"
    if "self-signed" in msg or "self signed" in msg:
        return "cert-self-signed", "low"
    if "hostname mismatch" in msg or "doesn't match" in msg or "ip address mismatch" in msg:
        return "cert-hostname-mismatch", "low"
    return "cert-untrusted", "low"


def _days_left(not_after: str, now: datetime) -> int | None:
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
    except (ValueError, OverflowError):
        return None
    return (expires - now).days


def _name(cert: dict, field: str) -> str:
    """Flatten getpeercert()'s nested subject/issuer tuples to 'CN=…, O=…'."""
    parts = []
    for rdn in cert.get(field) or ():
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                parts.append(f"{'CN' if key == 'commonName' else 'O'}={value}")
    return ", ".join(parts)


@dataclass
class _Snapshot:
    version: str | None
    cipher: tuple | None
    cert: dict | None


async def _handshake(host: str, port: int, ctx: ssl.SSLContext) -> _Snapshot:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), TIMEOUT
    )
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        # Copy what we need before the connection closes
        return _Snapshot(ssl_obj.version(), ssl_obj.cipher(), ssl_obj.getpeercert())
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


def _verify_context() -> ssl.SSLContext:
    """Browser-like verification against the system CA store."""
    return ssl.create_default_context()


def _legacy_context() -> ssl.SSLContext | None:
    """Client context that offers only TLS 1.0/1.1, or None if OpenSSL refuses."""
    try:
        with warnings.catch_warnings():
            # Offering TLS 1.0/1.1 is the point here; silence Python's deprecation notice
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return ctx


async def check_host(
    host: dict,
    *,
    legacy: bool = False,
    limiter: RateLimiter | None = None,
    now: datetime | None = None,
) -> tuple[dict | None, list[dict]]:
    """Return (tls info, findings) for one probed host; (None, []) if not HTTPS."""
    url = host.get("url") or ""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None, []
    name, port = parsed.hostname, parsed.port or 443
    now = now or datetime.now(UTC)
    findings: list[tuple[str, str, str]] = []
    info: dict = {"host": host.get("host", name), "url": url}

    reachable = True  # the server completed or at least answered a TLS handshake
    if limiter:
        await limiter.wait()
    try:
        snap = await _handshake(name, port, _verify_context())
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
        check, sev = _classify_verify_error(reason)
        findings.append((check, sev, f"Certificate verification failed: {reason}"))
        info["verified"] = False
        info["error"] = reason
    except (
        Exception
    ) as exc:  # DNS, refused, timeout, IDN encoding… — one host must not abort the scan
        reachable = False
        info["verified"] = False
        info["error"] = f"{type(exc).__name__}: {exc}"[:200]
    else:
        info.update(verified=True, protocol=snap.version, cipher=(snap.cipher or ("",))[0])
        cert = snap.cert or {}
        info["issuer"] = _name(cert, "issuer")
        info["not_after"] = cert.get("notAfter", "")
        days = _days_left(info["not_after"], now) if info["not_after"] else None
        info["days_left"] = days
        if days is not None and days < EXPIRY_WARN_DAYS:
            findings.append(
                ("cert-expiring-soon", "info", f"Certificate expires in {days} day(s).")
            )

    if legacy and reachable:
        ctx = _legacy_context()
        if ctx is None:
            info["legacy_tls"] = "untestable"
        else:
            if limiter:
                await limiter.wait()
            try:
                snap = await _handshake(name, port, ctx)
            except Exception:
                info["legacy_tls"] = "rejected"
            else:
                info["legacy_tls"] = snap.version or "accepted"
                findings.append(
                    ("legacy-tls", "low", f"Server still accepts {snap.version or 'TLS 1.0/1.1'}.")
                )

    return info, [
        asdict(TlsFinding(info["host"], url, check, sev, detail)) for check, sev, detail in findings
    ]


async def check_tls(
    hosts: list[dict], *, legacy: bool = False, limiter: RateLimiter | None = None
) -> tuple[list[dict], list[dict]]:
    """Check every HTTPS host. Returns (per-host info, flat findings)."""
    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded(h: dict):
        async with sem:
            return await check_host(h, legacy=legacy, limiter=limiter)

    pairs = await asyncio.gather(*(bounded(h) for h in hosts))
    infos = [i for i, _ in pairs if i is not None]
    findings = [f for _, fs in pairs for f in fs]
    return infos, findings
