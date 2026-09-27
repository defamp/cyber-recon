"""CLI entry point."""
import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich.console import Console

from .modules.subdomains import enumerate_subdomains
from .modules.http_probe import probe_targets
from .modules.wayback import fetch_wayback_urls
from .modules.secrets import scan_secrets
from .modules.cors import check_cors_reflection
from .modules.nuclei import run_nuclei, nuclei_available
from .batch import load_batch, TargetConfig
from .notify import notify_webhook, parse_webhook_target
from .reporting.markdown import write_markdown_report
from .reporting.html_report import write_html_report

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Passive recon orchestrator for VDP/bug bounty targets",
    )
    p.add_argument("--target", help="Root domain (single-target mode)")
    p.add_argument("--output", help="Output directory (single-target mode)")
    p.add_argument("--batch", help="YAML file with multiple targets (batch mode)")
    p.add_argument("--active", action="store_true",
                   help="Enable active modules (CORS reflection probe, Nuclei)")
    p.add_argument("--nuclei", action="store_true",
                   help="Run Nuclei scan on live hosts (requires nuclei binary)")
    p.add_argument("--nuclei-templates", help="Comma-separated nuclei template tags/paths")
    p.add_argument("--webhook", help="Webhook URL for notifications (slack:URL or discord:URL)")
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--no-wayback", action="store_true")
    p.add_argument("--no-secrets", action="store_true")
    p.add_argument("--no-html", action="store_true",
                   help="Skip HTML report (still emits Markdown + JSON)")
    return p.parse_args()


async def run_one(cfg: TargetConfig, *, no_html: bool, extra_active: bool = False,
                  extra_nuclei: bool = False, nuclei_templates: list[str] | None = None,
                  webhook: str | None = None) -> dict:
    target = cfg.domain
    out_dir = Path(cfg.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    active = cfg.active or extra_active
    nuclei = cfg.nuclei or extra_nuclei

    skip = set(cfg.skip or [])
    if skip:
        console.print(f"[dim]Skipping modules: {sorted(skip)}[/dim]")

    results: dict = {
        "target": target,
        "subdomains": [],
        "alive": [],
        "urls": [],
        "secrets": [],
        "nuclei": [],
        "cors_reflective": {},
    }

    if "subdomains" not in skip:
        with console.status(f"[bold green]Enumerating subdomains for {target}..."):
            results["subdomains"] = await enumerate_subdomains(target)
        console.print(f"  [green]✓[/green] {len(results['subdomains'])} subdomains")

    if results["subdomains"] and "http" not in skip:
        with console.status("[bold green]Probing live hosts..."):
            results["alive"] = await probe_targets(results["subdomains"])
        console.print(f"  [green]✓[/green] {len(results['alive'])} live hosts")

    if "wayback" not in skip:
        with console.status("[bold green]Fetching Wayback URLs..."):
            results["urls"] = await fetch_wayback_urls(target)
        console.print(f"  [green]✓[/green] {len(results['urls'])} historical URLs")

    if "secrets" not in skip and results["urls"]:
        with console.status("[bold green]Scanning JS files for secrets..."):
            results["secrets"] = await scan_secrets(results["urls"])
        console.print(f"  [green]✓[/green] {len(results['secrets'])} potential secrets")

    if active and results["alive"]:
        with console.status("[bold yellow]Testing CORS reflection (active)..."):
            results["cors_reflective"] = await check_cors_reflection(results["alive"])
        n_reflect = sum(1 for v in results["cors_reflective"].values() if v.get("reflects"))
        console.print(f"  [yellow]⚠[/yellow] {n_reflect}/{len(results['alive'])} hosts reflect Origin")

    if nuclei and results["alive"]:
        if not nuclei_available():
            console.print("  [yellow]⚠ nuclei binary not found — skipping[/yellow]")
            results["nuclei"] = [{"_warning": "nuclei binary not found in PATH"}]
        else:
            with console.status("[bold yellow]Running Nuclei scan (active)..."):
                results["nuclei"] = await run_nuclei(
                    results["alive"],
                    templates=nuclei_templates,
                )
            real = [f for f in results["nuclei"] if not f.get("_warning")]
            console.print(f"  [yellow]⚠[/yellow] {len(real)} Nuclei findings")

    # Write artifacts
    json_path = out_dir / "results.json"
    json_path.write_text(json.dumps(results, indent=2, default=str))
    md_path = out_dir / "report.md"
    write_markdown_report(results, md_path)
    console.print(f"\n[bold cyan]Markdown:[/bold cyan] {md_path}")
    console.print(f"[bold cyan]JSON:     [/bold cyan] {json_path}")
    if not no_html:
        html_path = out_dir / "report.html"
        write_html_report(results, html_path)
        console.print(f"[bold cyan]HTML:     [/bold cyan] {html_path}")

    # Webhook notification
    if webhook:
        platform, url = parse_webhook_target(webhook)
        with console.status(f"[bold magenta]Posting summary to {platform} webhook..."):
            ok = await notify_webhook(url, results, platform=platform)
        if ok:
            console.print(f"  [green]✓[/green] notified {platform}")
        else:
            console.print(f"  [red]✗[/red] webhook notification failed")

    return results


async def run_batch(path: Path, *, no_html: bool, active: bool, nuclei: bool,
                    nuclei_templates: list[str] | None, webhook: str | None) -> int:
    targets = load_batch(path)
    console.print(f"[bold]Loaded {len(targets)} target(s) from {path}[/bold]")
    failures = 0
    for cfg in targets:
        console.rule(f"[bold cyan]{cfg.domain}[/bold cyan]")
        try:
            await run_one(
                cfg,
                no_html=no_html,
                extra_active=active,
                extra_nuclei=nuclei,
                nuclei_templates=nuclei_templates,
                webhook=(webhook or cfg.notify.get("webhook")),
            )
        except Exception as exc:
            failures += 1
            console.print(f"[red]✗ {cfg.domain} failed: {exc}[/red]")
    return 0 if failures == 0 else 1


async def run(args: argparse.Namespace) -> int:
    if args.batch:
        return await run_batch(
            Path(args.batch),
            no_html=args.no_html,
            active=args.active,
            nuclei=args.nuclei,
            nuclei_templates=args.nuclei_templates.split(",") if args.nuclei_templates else None,
            webhook=args.webhook,
        )

    if not args.target or not args.output:
        console.print("[red]Either --target/--output or --batch is required.[/red]")
        return 2

    cfg = TargetConfig(domain=args.target, output=args.output,
                       active=args.active, nuclei=args.nuclei)
    await run_one(
        cfg,
        no_html=args.no_html,
        nuclei_templates=args.nuclei_templates.split(",") if args.nuclei_templates else None,
        webhook=args.webhook,
    )
    return 0


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[red]Aborted.[/red]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
