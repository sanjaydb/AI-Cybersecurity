"""Find likely secrets in local source and config files.

This is a defender tool. It never sends file contents to a network service.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"
}
TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env", ".ini",
    ".toml", ".md", ".txt", ".cfg", ".xml", ".html", ".sh", ".ps1", ".c",
    ".h", ".java", ".go", ".rb", ".php",
}

PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
    ("password_assign", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_like", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
]

HIGH_ENTROPY_ASSIGN = re.compile(
    r"(?i)(token|secret|key|password)\s*[=:]\s*['\"]([A-Za-z0-9/+=_\-]{20,})['\"]"
)


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    snippet: str
    severity: str = "high"

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        for rule, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(rule=rule, path=path, line=idx, snippet=line.strip()[:180])
                )
        entropy_hit = HIGH_ENTROPY_ASSIGN.search(line)
        if entropy_hit and shannon_entropy(entropy_hit.group(2)) >= 3.5:
            findings.append(
                Finding(
                    rule="high_entropy_secret",
                    path=path,
                    line=idx,
                    snippet=line.strip()[:180],
                    severity="medium",
                )
            )
    return findings


def scan_path(root: str | Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in iter_files(Path(root)):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(text, str(file_path)))
    return findings
