"""Webhook notifier — posts recon findings summary to Slack or Discord.

Both platforms accept JSON POST with simple `text`/`content` + `attachments`.
We use the most-compatible subset.
"""

import aiohttp

from .modules.secrets import secret_sort_key
from .monitor import format_alert

TIMEOUT = 10


def _severity_color(sev: str) -> str:
    return {
        "critical": "#f85149",
        "high": "#db6d28",
        "medium": "#d29922",
        "low": "#58a6ff",
        "info": "#8b949e",
    }.get((sev or "").lower(), "#8b949e")


def _build_slack_payload(results: dict, *, include_findings: bool = True) -> dict:
    """Build a Slack-compatible webhook payload."""
    target = results.get("target", "?")
    n_subs = len(results.get("subdomains", []))
    n_alive = len(results.get("alive", []))
    n_urls = len(results.get("urls", []))
    n_secrets = len(results.get("secrets", []))
    n_nuclei = len(results.get("nuclei", []))

    fields = [
        {"title": "Subdomains", "value": str(n_subs), "short": True},
        {"title": "Live hosts", "value": str(n_alive), "short": True},
        {"title": "Hist. URLs", "value": str(n_urls), "short": True},
        {"title": "Secrets", "value": str(n_secrets), "short": True},
    ]
    if n_nuclei:
        fields.append({"title": "Nuclei hits", "value": str(n_nuclei), "short": True})

    attachments: list[dict] = [
        {
            "color": "#f85149" if n_secrets > 0 else "#3fb950",
            "title": f"Recon summary — {target}",
            "fields": fields,
            "footer": "cyber-recon",
        }
    ]

    if include_findings and results.get("secrets"):
        # add top secrets as text
        lines = ["*Top potential secrets:*"]
        for s in sorted(results["secrets"], key=secret_sort_key)[:5]:
            conf = s.get("confidence", "?")
            lines.append(f"• `{s.get('pattern', '')}` ({conf}) in `{s.get('url', '')[:60]}`")
        attachments.append(
            {
                "color": "#f85149",
                "text": "\n".join(lines),
            }
        )

    return {"text": f":mag: Recon finished for `{target}`", "attachments": attachments}


def _build_discord_payload(results: dict) -> dict:
    """Build Discord-compatible webhook payload."""
    target = results.get("target", "?")
    n_subs = len(results.get("subdomains", []))
    n_alive = len(results.get("alive", []))
    n_secrets = len(results.get("secrets", []))
    n_nuclei = len(results.get("nuclei", []))

    color = 0xF85149 if n_secrets > 0 else 0x3FB950
    description = (
        f"**Subdomains:** {n_subs}\n"
        f"**Live hosts:** {n_alive}\n"
        f"**Secrets:** {n_secrets}\n"
        f"**Nuclei hits:** {n_nuclei}"
    )
    return {
        "content": f":mag: Recon finished for `{target}`",
        "embeds": [
            {
                "title": f"Recon summary — {target}",
                "description": description,
                "color": color,
                "footer": {"text": "cyber-recon"},
            }
        ],
    }


DISCORD_CONTENT_LIMIT = 2000  # Discord rejects longer message content


def _build_alert_payload(target: str, alerts: dict[str, list[str]], platform: str) -> dict:
    body = format_alert(target, alerts)
    if platform == "discord":
        if len(body) > DISCORD_CONTENT_LIMIT:
            body = body[: DISCORD_CONTENT_LIMIT - 20] + "\n… (see diff.json)"
        return {"content": body}
    return {"text": f":rotating_light: {body}"}


async def notify_alert(
    url: str, target: str, alerts: dict[str, list[str]], *, platform: str = "slack"
) -> bool:
    """Post a "new since last scan" alert. Returns True on 2xx."""
    if not url:
        return False
    platform = (platform or "slack").lower()
    return await _post(url, _build_alert_payload(target, alerts, platform))


async def notify_webhook(url: str, results: dict, *, platform: str = "slack") -> bool:
    """Post results to a webhook. Returns True on 2xx."""
    if not url:
        return False
    platform = (platform or "slack").lower()
    if platform == "discord":
        payload = _build_discord_payload(results)
    else:
        payload = _build_slack_payload(results)
    return await _post(url, payload)


async def _post(url: str, payload: dict) -> bool:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as r:
                return 200 <= r.status < 300
    except Exception:
        return False


def parse_webhook_target(spec: str) -> tuple[str, str]:
    """Parse 'slack:https://...' or 'discord:https://...' or just URL (slack default)."""
    if "://" in spec:
        if spec.startswith(("http://", "https://")):
            return ("slack", spec)
    if ":" in spec:
        plat, url = spec.split(":", 1)
        return (plat.lower(), url)
    return ("slack", spec)
