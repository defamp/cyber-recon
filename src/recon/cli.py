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
from .reporting.markdown import write_markdown_report

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Passive recon orchestrator for VDP/bug bounty targets",
    )
    p.add_argument("--target", required=True, help="Root domain (e.g. example.com)")
    p.add_argument("--output", required=True, help="Output directory")
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--no-wayback", action="store_true")
    p.add_argument("--no-secrets", action="store_true")
    return p.parse_args()


async def run(target: str, args: argparse.Namespace) -> dict:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: dict = {"target": target, "subdomains": [], "alive": [], "urls": [], "secrets": []}

    if not args.no_subdomains:
        with console.status(f"[bold green]Enumerating subdomains for {target}..."):
            results["subdomains"] = await enumerate_subdomains(target)
        console.print(f"  [green]✓[/green] {len(results['subdomains'])} subdomains")

    if results["subdomains"]:
        with console.status("[bold green]Probing live hosts..."):
            results["alive"] = await probe_targets(results["subdomains"])
        console.print(f"  [green]✓[/green] {len(results['alive'])} live hosts")

    if not args.no_wayback:
        with console.status("[bold green]Fetching Wayback URLs..."):
            results["urls"] = await fetch_wayback_urls(target)
        console.print(f"  [green]✓[/green] {len(results['urls'])} historical URLs")

    if not args.no_secrets and results["urls"]:
        with console.status("[bold green]Scanning JS files for secrets..."):
            results["secrets"] = await scan_secrets(results["urls"])
        console.print(f"  [green]✓[/green] {len(results['secrets'])} potential secrets")

    json_path = out_dir / "results.json"
    json_path.write_text(json.dumps(results, indent=2, default=str))
    md_path = out_dir / "report.md"
    write_markdown_report(results, md_path)

    console.print(f"\n[bold cyan]Report:[/bold cyan] {md_path}")
    console.print(f"[bold cyan]JSON:  [/bold cyan] {json_path}")
    return results


def main() -> int:
    args = parse_args()
    try:
        asyncio.run(run(args.target, args))
    except KeyboardInterrupt:
        console.print("\n[red]Aborted.[/red]")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
