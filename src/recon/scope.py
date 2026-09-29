"""Scope control — decide which hosts the tool may send requests to.

Scope file formats:

YAML::

    include:
      - "*.example.com"        # any subdomain (not the apex itself)
      - example.com            # exact host
      - "re:^api\\d+\\.example\\.org$"   # regex, full match on the hostname
    exclude:
      - legacy.example.com
    rate_limit: 5              # optional, requests/second against targets

Plain text (one entry per line, ``!`` prefix = exclude, ``#`` = comment)::

    *.example.com
    !legacy.example.com

URLs are accepted too (``https://app.example.com/path``); only the hostname is
used. Exclusions always win over inclusions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


def normalize_host(value: str) -> str:
    """Lowercase hostname without scheme, path, port or trailing dot."""
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
        if value.count(":") == 1:  # host:port (IPv6 literals are left alone)
            value = value.split(":", 1)[0]
    return value.rstrip(".")


@dataclass(frozen=True)
class _Rule:
    raw: str
    kind: str  # "exact" | "wildcard" | "regex"
    value: str
    pattern: re.Pattern | None = None

    @classmethod
    def parse(cls, entry: str) -> _Rule:
        entry = entry.strip()
        if entry.lower().startswith("re:"):
            expr = entry[3:].strip()
            try:
                return cls(entry, "regex", expr, re.compile(expr, re.IGNORECASE))
            except re.error as exc:
                raise ValueError(f"invalid scope regex {expr!r}: {exc}") from exc
        host = normalize_host(entry)
        if host.startswith("*."):
            return cls(entry, "wildcard", host[1:])  # keep the leading dot
        if not host or "*" in host:
            raise ValueError(f"unsupported scope entry: {entry!r}")
        return cls(entry, "exact", host)

    def matches(self, host: str) -> bool:
        if self.kind == "exact":
            return host == self.value
        if self.kind == "wildcard":
            return host.endswith(self.value)
        assert self.pattern is not None
        return self.pattern.fullmatch(host) is not None


@dataclass
class Scope:
    include: list[_Rule] = field(default_factory=list)
    exclude: list[_Rule] = field(default_factory=list)
    rate_limit: float | None = None
    source: str = "default"

    @classmethod
    def from_entries(
        cls,
        include: list[str],
        exclude: list[str] | None = None,
        *,
        rate_limit: float | None = None,
        source: str = "inline",
    ) -> Scope:
        if not include:
            raise ValueError("scope needs at least one include entry")
        return cls(
            include=[_Rule.parse(e) for e in include],
            exclude=[_Rule.parse(e) for e in exclude or []],
            rate_limit=rate_limit,
            source=source,
        )

    @classmethod
    def default_for(cls, domain: str) -> Scope:
        """The implicit scope: the target domain and all of its subdomains."""
        d = normalize_host(domain)
        return cls.from_entries([d, f"*.{d}"], source="default")

    def in_scope(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if any(r.matches(host) for r in self.exclude):
            return False
        return any(r.matches(host) for r in self.include)

    def url_in_scope(self, url: str) -> bool:
        try:
            return self.in_scope(urlparse(url).hostname or "")
        except ValueError:
            return False

    def exact_hosts(self) -> list[str]:
        """Hosts listed literally (not wildcard/regex) that are not excluded."""
        return sorted({r.value for r in self.include if r.kind == "exact"} - self._excluded())

    def _excluded(self) -> set[str]:
        return {r.value for r in self.include if any(x.matches(r.value) for x in self.exclude)}

    def summary(self) -> dict:
        return {
            "source": self.source,
            "include": [r.raw for r in self.include],
            "exclude": [r.raw for r in self.exclude],
            "rate_limit": self.rate_limit,
        }


def load_scope(path: Path) -> Scope:
    text = path.read_text()
    data = None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        pass  # not YAML — fall through to the line format
    if isinstance(data, dict):
        rate = data.get("rate_limit")
        return Scope.from_entries(
            [str(e) for e in data.get("include") or []],
            [str(e) for e in data.get("exclude") or []],
            rate_limit=float(rate) if rate is not None else None,
            source=str(path),
        )
    include: list[str] = []
    exclude: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("!"):
            exclude.append(line[1:])
        else:
            include.append(line)
    return Scope.from_entries(include, exclude, source=str(path))
