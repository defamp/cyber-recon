"""Batch loader — read multi-target YAML config and yield target configs."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TargetConfig:
    domain: str
    output: str
    active: bool = False
    nuclei: bool = False
    skip: list[str] = field(default_factory=list)
    notify: dict[str, Any] = field(default_factory=dict)
    scope: str | None = None  # path to a scope file (see recon.scope)
    rate: float | None = None  # max requests/second against the target

    @classmethod
    def from_dict(cls, d: dict) -> "TargetConfig":
        if "domain" not in d:
            raise ValueError(f"target entry missing 'domain': {d}")
        return cls(
            domain=d["domain"],
            output=d.get("output", f"output/{d['domain']}"),
            active=d.get("active", False),
            nuclei=d.get("nuclei", False),
            skip=d.get("skip", []),
            notify=d.get("notify", {}),
            scope=d.get("scope"),
            rate=d.get("rate"),
        )


def load_batch(path: Path) -> list[TargetConfig]:
    """Load YAML config with shape:

    targets:
      - domain: example.com
        output: output/example
        active: false
        nuclei: true
      - domain: foo.com
        ...
    """
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict) or "targets" not in data:
        raise ValueError(f"batch file must have top-level 'targets' key: {path}")
    raw_targets = data["targets"]
    if not isinstance(raw_targets, list):
        raise ValueError(f"'targets' must be a list: {path}")
    return [TargetConfig.from_dict(t) for t in raw_targets]
