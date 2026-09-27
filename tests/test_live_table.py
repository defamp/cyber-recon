from io import StringIO

from rich.console import Console

from recon.live_table import LiveNucleiTable, render_table


def _finding(sev, name="Test", template="cve-2021-44228", matched="https://x.com/"):
    return {
        "template-id": template,
        "matched-at": matched,
        "info": {"severity": sev, "name": name, "description": "log4j vuln"},
    }


def test_render_table_empty():
    t = render_table([])
    assert t is not None


def test_render_table_excludes_warnings():
    t = render_table([{"_warning": "nuclei not found"}])
    # the warning row should not appear; table has only headers
    rendered = _to_text(t)
    assert "nuclei not found" not in rendered


def test_render_table_includes_findings():
    t = render_table([_finding("critical", "Log4Shell")])
    rendered = _to_text(t)
    assert "Log4Shell" in rendered
    assert "cve-2021-44228" in rendered


def test_render_table_unknown_severity_does_not_crash():
    t = render_table([_finding("bogus")])
    rendered = _to_text(t)
    assert "BOGUS" in rendered.upper()


def _to_text(table) -> str:
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=200).print(table)
    return buf.getvalue()


def test_live_nuclei_table_accumulates_findings():
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    with LiveNucleiTable(console=console) as lt:
        lt.add(_finding("critical", "Log4Shell"))
        lt.add(_finding("high", "Spring4Shell"))
    assert len(lt.findings) == 2
