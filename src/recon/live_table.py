"""Rich live table for Nuclei findings — color-coded by severity."""

from __future__ import annotations

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .modules.nuclei import finding_name

SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold white on dark_orange3",
    "medium": "black on yellow",
    "low": "white on dodger_blue3",
    "info": "dim",
}


def render_table(findings: list[dict]) -> Table:
    table = Table(
        title="Nuclei findings",
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Template", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Matched at", overflow="fold")
    table.add_column("Info", overflow="fold")

    for f in findings:
        if not isinstance(f, dict) or f.get("_warning"):
            continue
        info = f.get("info") or {}
        sev = (info.get("severity") or "info").lower()
        template = f.get("template-id") or ""
        name = finding_name(f)
        matched = f.get("matched-at") or ""
        desc = (info.get("description") or "")[:140]
        sev_cell = f"[{SEV_STYLE.get(sev, 'dim')}]{sev.upper():>8}[/]"
        table.add_row(sev_cell, template, name, matched, desc)
    return table


class LiveNucleiTable:
    """Context manager that shows a Nuclei results table updating live."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._live: Live | None = None
        self.findings: list[dict] = []

    def __enter__(self):
        self._live = Live(self.render(), console=self.console, refresh_per_second=4)
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._live:
            self._live.__exit__(exc_type, exc, tb)
            self._live = None

    def add(self, finding: dict) -> None:
        self.findings.append(finding)
        if self._live:
            self._live.update(self.render())

    def render(self) -> Table:
        return render_table(self.findings)
