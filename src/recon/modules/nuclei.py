"""Nuclei wrapper — invokes the nuclei binary if available.

Falls back gracefully if nuclei is not installed. Only runs when explicit
opt-in `--nuclei` flag is set so default behavior remains passive.
"""

import asyncio
import json
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path

NUCLEI_BIN = shutil.which("nuclei")
SEVERITIES = ["critical", "high", "medium"]


async def run_nuclei(
    hosts: Iterable[dict],
    *,
    severity: list[str] | None = None,
    templates: list[str] | None = None,
    timeout: int = 300,
) -> list[dict]:
    """Run nuclei against live hosts. Returns parsed JSON findings.

    Each finding dict has: template-id, name, severity, host, matched-at,
    info, etc. Empty list if nuclei is not installed.
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

    cmd = [
        NUCLEI_BIN,
        "-l",
        targets_path,
        "-json",
        "-severity",
        ",".join(sev),
        "-silent",
        "-no-update-check",
        "-timeout",
        "5",
        "-retries",
        "1",
    ]
    if templates:
        cmd.extend(["-t", ",".join(templates)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (TimeoutError, FileNotFoundError, PermissionError) as exc:
        return [{"_warning": f"nuclei execution failed: {exc}"}]
    finally:
        Path(targets_path).unlink(missing_ok=True)

    findings: list[dict] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def nuclei_available() -> bool:
    return NUCLEI_BIN is not None
