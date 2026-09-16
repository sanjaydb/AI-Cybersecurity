"""Unsupervised anomaly hints on local log files.

Uses IsolationForest on simple numeric features extracted from each line.
This is a teaching model, not a SOC-grade detector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

STATUS_RE = re.compile(r"\s(\d{3})\s")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
PATH_RE = re.compile(r"\"(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+([^\s]+)")


@dataclass
class LogAnomaly:
    line: int
    score: float
    text: str
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _features(line: str) -> list[float]:
    status_match = STATUS_RE.search(line)
    status = int(status_match.group(1)) if status_match else 200
    path_match = PATH_RE.search(line)
    path = path_match.group(1) if path_match else ""
    return [
        float(len(line)),
        float(status),
        float(line.count("/")),
        float(int(bool(re.search(r"(?i)(union|select|script|\.\./|%27|%3c)", line)))),
        float(int("'" in line or "\"" in line)),
        float(len(path)),
        float(int(path.endswith((".php", ".asp", ".exe")))),
    ]


def _reasons(line: str, status: int | None) -> list[str]:
    hints: list[str] = []
    if status and status >= 500:
        hints.append("server_error_status")
    if status and status == 401 or status == 403:
        hints.append("auth_failure_status")
    if re.search(r"(?i)(union\s+select|or\s+1=1|\.\./\.\./)", line):
        hints.append("injection_or_traversal_tokens")
    if len(line) > 400:
        hints.append("unusually_long_line")
    return hints or ["statistical_outlier"]


def analyze_log(path: str | Path, contamination: float = 0.08) -> list[LogAnomaly]:
    raw_lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    lines = [ln for ln in raw_lines if ln.strip()]
    if len(lines) < 8:
        raise ValueError("Need at least 8 log lines to fit an anomaly model.")

    matrix = np.array([_features(ln) for ln in lines], dtype=float)
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    labels = model.fit_predict(matrix)
    scores = model.decision_function(matrix)

    anomalies: list[LogAnomaly] = []
    for idx, (label, score, text) in enumerate(zip(labels, scores, lines), start=1):
        if label == -1:
            status_match = STATUS_RE.search(text)
            status = int(status_match.group(1)) if status_match else None
            anomalies.append(
                LogAnomaly(
                    line=idx,
                    score=round(float(score), 4),
                    text=text[:240],
                    reasons=_reasons(text, status),
                )
            )
    anomalies.sort(key=lambda item: item.score)
    return anomalies
