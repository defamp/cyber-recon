"""Nuclei wrapper — invokes the nuclei binary if available.

Falls back gracefully if nuclei is not installed. Only runs when explicit
opt-in `--nuclei` flag is set so default behavior remains passive.
"""

import asyncio
import json
import shutil
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

NUCLEI_BIN = shutil.which("nuclei")
SEVERITIES = ["critical", "high", "medium"]


async def run_nuclei(
    hosts: Iterable[dict],
    *,
    severity: list[str] | None = None,
    templates: list[str] | None = None,
    tags: list[str] | None = None,
    timeout: int = 300,
    rate_limit: float | None = None,
    on_finding: Callable[[dict], None] | None = None,
) -> list[dict]:
    """Run nuclei against live hosts. Returns parsed JSON findings.

    Each finding dict has: template-id, name, severity, host, matched-at,
    info, etc. Empty list if nuclei is not installed. ``on_finding`` is called
    for each finding as soon as nuclei emits it (used by the live table).
    """
    urls = [h["url"] for h in hosts if h.get("url")]
    if not urls:
        return []
    if NUCLEI_BIN is None:
        return [{"_warning": "nuclei binary not found in PATH — skipping"}]

    sev = severity or SEVERITIES
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        for u in urls:
            f.write(u + "\n")
        targets_path = f.name

    # Flags per nuclei v3 (`-json`/`-no-update-check` were removed and make nuclei exit 2)
    cmd = [
        NUCLEI_BIN,
        "-l",
        targets_path,
        "-jsonl",
        "-severity",
        ",".join(sev),
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-timeout",
        "5",
        "-retries",
        "1",
    ]
    if templates:
        cmd.extend(["-t", ",".join(templates)])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    if rate_limit:
        # nuclei's -rl takes whole requests/second; limits below 1 are clamped to 1
        cmd.extend(["-rl", str(max(1, int(rate_limit)))])

    findings: list[dict] = []

    async def _read_stdout(stream: asyncio.StreamReader) -> None:
        while line := await stream.readline():
            text = line.decode(errors="ignore").strip()
            if not text:
                continue
            try:
                finding = json.loads(text)
            except json.JSONDecodeError:
                continue
            findings.append(finding)
            if on_finding:
                on_finding(finding)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None and proc.stderr is not None
        stderr_task = asyncio.ensure_future(proc.stderr.read())
        await asyncio.wait_for(_read_stdout(proc.stdout), timeout=timeout)
        stderr = await stderr_task
        returncode = await proc.wait()
    except TimeoutError:
        if proc and proc.returncode is None:
            proc.kill()
            await proc.wait()
        return findings + [{"_warning": f"nuclei timed out after {timeout}s (partial results)"}]
    except (FileNotFoundError, PermissionError) as exc:
        return [{"_warning": f"nuclei execution failed: {exc}"}]
    finally:
        Path(targets_path).unlink(missing_ok=True)

    if returncode != 0:
        detail = stderr.decode(errors="ignore").strip().splitlines()
        msg = detail[-1] if detail else "no output"
        findings.append({"_warning": f"nuclei exited with code {returncode}: {msg[:200]}"})
    return findings


def nuclei_available() -> bool:
    return NUCLEI_BIN is not None
