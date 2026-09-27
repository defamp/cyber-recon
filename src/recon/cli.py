"""CLI entry point."""

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from .batch import TargetConfig, load_batch
from .diff import diff_results
from .live_table import LiveNucleiTable
from .modules.advisories import enrich_nuclei
from .modules.cors import check_cors_reflection
from .modules.http_probe import probe_targets
from .modules.nuclei import nuclei_available, run_nuclei
from .modules.secrets import scan_secrets
from .modules.subdomains import enumerate_subdomains
from .modules.wayback import fetch_wayback_urls
from .notify import notify_webhook, parse_webhook_target
from .plugins import discover as discover_user_plugins
from .plugins import list_plugins, run_plugins
from .reporting.html_report import write_html_report
from .reporting.markdown import write_markdown_report

console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Passive recon orchestrator for VDP/bug bounty targets",
    )
    p.add_argument("--target", help="Root domain (single-target mode)")
    p.add_argument("--output", help="Output directory (single-target mode)")
    p.add_argument("--batch", help="YAML file with multiple targets (batch mode)")
    p.add_argument(
        "--active",
        action="store_true",
        help="Enable active modules (CORS reflection probe, Nuclei)",
    )
    p.add_argument(
        "--nuclei",
        action="store_true",
        help="Run Nuclei scan on live hosts (requires nuclei binary)",
    )
    p.add_argument("--nuclei-templates", help="Comma-separated nuclei template tags/paths")
    p.add_argument(
        "--nuclei-live", action="store_true", help="Stream Nuclei findings into a live rich table"
    )
    p.add_argument(
        "--enrich-cve",
        action="store_true",
        help="Enrich CVE-tagged Nuclei findings with GitHub advisory data",
    )
    p.add_argument("--diff", help="Path to baseline results.json — emit delta report")
    p.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="Run a named plugin (repeatable). e.g. --plugin severity_counter",
    )
    p.add_argument("--list-plugins", action="store_true", help="List registered plugins and exit")
    p.add_argument("--webhook", help="Webhook URL for notifications (slack:URL or discord:URL)")
    p.add_argument("--no-subdomains", action="store_true")
    p.add_argument("--no-wayback", action="store_true")
    p.add_argument("--no-secrets", action="store_true")
    p.add_argument(
        "--no-html", action="store_true", help="Skip HTML report (still emits Markdown + JSON)"
    )
    p.add_argument(
        "--no-plugins", action="store_true", help="Skip auto-running active_default bundled plugins"
    )
    return p.parse_args()


async def run_one(
    cfg: TargetConfig,
    *,
    no_html: bool,
    extra_active: bool = False,
    extra_nuclei: bool = False,
    nuclei_templates: list[str] | None = None,
    webhook: str | None = None,
    nuclei_live: bool = False,
    enrich_cve: bool = False,
    plugin_names: list[str] | None = None,
    run_default_plugins: bool = True,
) -> dict:
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
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "subdomains": [],
        "alive": [],
        "urls": [],
        "secrets": [],
        "nuclei": [],
        "cors_reflective": {},
        "errors": [],
    }
    errors: list[str] = results["errors"]

    def report_errors(start: int) -> None:
        for msg in errors[start:]:
            console.print(f"    [red]✗[/red] {msg}")

    if "subdomains" not in skip:
        n_err = len(errors)
        with console.status(f"[bold green]Enumerating subdomains for {target}..."):
            results["subdomains"] = await enumerate_subdomains(target, errors)
        mark = "[green]✓[/green]" if len(errors) == n_err else "[yellow]⚠[/yellow]"
        console.print(f"  {mark} {len(results['subdomains'])} subdomains")
        report_errors(n_err)

    if results["subdomains"] and "http" not in skip:
        with console.status("[bold green]Probing live hosts..."):
            results["alive"] = await probe_targets(results["subdomains"])
        console.print(f"  [green]✓[/green] {len(results['alive'])} live hosts")

    if "wayback" not in skip:
        n_err = len(errors)
        with console.status("[bold green]Fetching Wayback URLs..."):
            results["urls"] = await fetch_wayback_urls(target, errors)
        mark = "[green]✓[/green]" if len(errors) == n_err else "[yellow]⚠[/yellow]"
        console.print(f"  {mark} {len(results['urls'])} historical URLs")
        report_errors(n_err)

    if "secrets" not in skip and results["urls"]:
        with console.status("[bold green]Scanning JS files for secrets..."):
            results["secrets"] = await scan_secrets(results["urls"])
        console.print(f"  [green]✓[/green] {len(results['secrets'])} potential secrets")

    if active and results["alive"]:
        with console.status("[bold yellow]Testing CORS reflection (active)..."):
            results["cors_reflective"] = await check_cors_reflection(results["alive"])
        n_reflect = sum(1 for v in results["cors_reflective"].values() if v.get("reflects"))
        console.print(
            f"  [yellow]⚠[/yellow] {n_reflect}/{len(results['alive'])} hosts reflect Origin"
        )

    if nuclei and results["alive"]:
        if not nuclei_available():
            console.print("  [yellow]⚠ nuclei binary not found — skipping[/yellow]")
            results["nuclei"] = [{"_warning": "nuclei binary not found in PATH"}]
            errors.append("nuclei: binary not found in PATH")
        else:
            if nuclei_live:
                with LiveNucleiTable(console) as table:
                    raw_nuclei = await run_nuclei(
                        results["alive"],
                        templates=nuclei_templates,
                        on_finding=table.add,
                    )
            else:
                with console.status("[bold yellow]Running Nuclei scan (active)..."):
                    raw_nuclei = await run_nuclei(
                        results["alive"],
                        templates=nuclei_templates,
                    )
            if enrich_cve:
                with console.status("[bold cyan]Enriching CVEs via GitHub advisories..."):
                    results["nuclei"] = await enrich_nuclei(raw_nuclei)
                console.print("  [cyan]✓[/cyan] CVE enrichment done")
            else:
                results["nuclei"] = raw_nuclei
            real = [f for f in results["nuclei"] if not f.get("_warning")]
            console.print(f"  [yellow]⚠[/yellow] {len(real)} Nuclei findings")
            n_err = len(errors)
            errors.extend(
                f"nuclei: {f['_warning']}" for f in results["nuclei"] if f.get("_warning")
            )
            report_errors(n_err)

    # Plugins (bundled + user-requested)
    if run_default_plugins or plugin_names:
        names = list(plugin_names or [])
        if run_default_plugins and not names:
            await run_plugins(results)
        elif names:
            await run_plugins(results, names)
        if "severity_summary" in results:
            sev = results["severity_summary"]
            console.print(
                f"  [cyan]i[/cyan] severities: "
                f"crit={sev.get('critical', 0)} high={sev.get('high', 0)} "
                f"med={sev.get('medium', 0)} low={sev.get('low', 0)} info={sev.get('info', 0)}"
            )

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
            console.print("  [red]✗[/red] webhook notification failed")

    return results


async def run_batch(
    path: Path,
    *,
    no_html: bool,
    active: bool,
    nuclei: bool,
    nuclei_templates: list[str] | None,
    webhook: str | None,
    enrich_cve: bool,
    plugin_names: list[str],
    run_default_plugins: bool,
    nuclei_live: bool = False,
) -> int:
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
                nuclei_live=nuclei_live,
                enrich_cve=enrich_cve,
                plugin_names=plugin_names,
                run_default_plugins=run_default_plugins,
            )
        except Exception as exc:
            failures += 1
            console.print(f"[red]✗ {cfg.domain} failed: {exc}[/red]")
    return 0 if failures == 0 else 1


async def run(args: argparse.Namespace) -> int:
    if args.list_plugins:
        console.print("[bold]Registered plugins:[/bold]")
        for p in list_plugins():
            default = (
                "[green]active by default[/green]" if p.active_default else "[dim]opt-in[/dim]"
            )
            console.print(
                f"  • [cyan]{p.name}[/cyan] ({p.source}) — {p.description or '(no description)'} — {default}"
            )
        return 0

    discovered = discover_user_plugins()
    if discovered:
        console.print(f"[dim]Discovered user plugins: {discovered}[/dim]")

    if args.batch:
        return await run_batch(
            Path(args.batch),
            no_html=args.no_html,
            active=args.active,
            nuclei=args.nuclei,
            nuclei_templates=args.nuclei_templates.split(",") if args.nuclei_templates else None,
            webhook=args.webhook,
            enrich_cve=args.enrich_cve,
            plugin_names=args.plugin,
            run_default_plugins=not args.no_plugins,
            nuclei_live=args.nuclei_live,
        )

    if not args.target or not args.output:
        console.print("[red]Either --target/--output or --batch is required.[/red]")
        return 2

    # Load the baseline *before* scanning: when it lives in the same output
    # directory (the documented usage), run_one would overwrite it first.
    baseline = None
    if args.diff:
        baseline_path = Path(args.diff)
        if not baseline_path.exists():
            console.print(f"[red]Baseline not found: {baseline_path}[/red]")
            return 3
        baseline = json.loads(baseline_path.read_text())

    skip = [
        name
        for name, flag in (
            ("subdomains", args.no_subdomains),
            ("wayback", args.no_wayback),
            ("secrets", args.no_secrets),
        )
        if flag
    ]
    cfg = TargetConfig(
        domain=args.target,
        output=args.output,
        active=args.active,
        nuclei=args.nuclei,
        skip=skip,
    )
    results = await run_one(
        cfg,
        no_html=args.no_html,
        nuclei_templates=args.nuclei_templates.split(",") if args.nuclei_templates else None,
        webhook=args.webhook,
        nuclei_live=args.nuclei_live,
        enrich_cve=args.enrich_cve,
        plugin_names=args.plugin,
        run_default_plugins=not args.no_plugins,
    )

    # Diff mode
    if baseline is not None:
        delta = diff_results(baseline, results)
        diff_path = Path(args.output) / "diff.json"
        diff_path.write_text(json.dumps(delta, indent=2, default=str))
        console.print(f"\n[bold cyan]Diff:[/bold cyan] {diff_path}")
        console.print(f"[bold]Summary:[/bold] {delta['summary']}")

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
