"""Lightweight static checks for common insecure coding patterns.

These rules teach the idea of SAST. They are not a replacement for
Semgrep, CodeQL, or a human review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator

from aicsec.secret_scan import SKIP_DIRS

CODE_SUFFIXES = {".py", ".js", ".ts", ".php", ".java", ".go", ".rb"}


@dataclass
class SastFinding:
    rule_id: str
    title: str
    cwe: str
    severity: str
    path: str
    line: int
    snippet: str
    advice: str

    def to_dict(self) -> dict:
        return asdict(self)


RULES = [
    {
        "id": "sql-string-concat",
        "title": "SQL built with string concatenation",
        "cwe": "CWE-89",
        "severity": "high",
        "pattern": re.compile(r"(?i)(select|insert|update|delete).{0,80}(\+|%|format\(|f['\"]).*"),
        "advice": "Use parameterized queries / bound parameters. Never glue user input into SQL.",
    },
    {
        "id": "command-concat",
        "title": "OS command built from untrusted strings",
        "cwe": "CWE-78",
        "severity": "high",
        "pattern": re.compile(r"(?i)(os\.system|subprocess\.(call|run|popen)|eval\(|exec\().*(\+|format\(|f['\"])"),
        "advice": "Avoid shell=True. Pass argument lists. Never eval user input.",
    },
    {
        "id": "weak-tls",
        "title": "TLS verification disabled",
        "cwe": "CWE-295",
        "severity": "medium",
        "pattern": re.compile(r"(?i)(verify\s*=\s*False|ssl._create_unverified_context|CURLOPT_SSL_VERIFYPEER.+0)"),
        "advice": "Keep certificate verification on. Fix the trust store instead of disabling TLS checks.",
    },
    {
        "id": "debug-true",
        "title": "Debug mode enabled",
        "cwe": "CWE-489",
        "severity": "medium",
        "pattern": re.compile(r"(?i)(debug\s*=\s*True|app\.run\(.*debug\s*=\s*True)"),
        "advice": "Disable debug in any deployed environment.",
    },
    {
        "id": "hardcoded-secret",
        "title": "Hardcoded credential-like assignment",
        "cwe": "CWE-798",
        "severity": "high",
        "pattern": re.compile(r"(?i)(password|api_key|secret)\s*=\s*['\"][^'\"]{4,}['\"]"),
        "advice": "Load secrets from a vault or environment variables, never from source.",
    },
]


def iter_code_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in CODE_SUFFIXES:
            yield path


def scan_path(root: str | Path) -> list[SastFinding]:
    findings: list[SastFinding] = []
    base = Path(root)
    for file_path in iter_code_files(base):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines, start=1):
            for rule in RULES:
                if rule["pattern"].search(line):
                    findings.append(
                        SastFinding(
                            rule_id=rule["id"],
                            title=rule["title"],
                            cwe=rule["cwe"],
                            severity=rule["severity"],
                            path=str(file_path),
                            line=idx,
                            snippet=line.strip()[:180],
                            advice=rule["advice"],
                        )
                    )
    return findings
