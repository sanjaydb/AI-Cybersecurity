"""Score security headers from a *saved* HTTP response file.

Do not point this at third-party websites. Save your own response:

    printf 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n' > /tmp/resp.txt
    python -m aicsec.cli headers /tmp/resp.txt
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

EXPECTED = {
    "strict-transport-security": "Stops browsers from using plain HTTP after the first HTTPS visit.",
    "content-security-policy": "Limits script, style, and frame sources to reduce XSS impact.",
    "x-content-type-options": "Disables MIME sniffing (use nosniff).",
    "x-frame-options": "Reduces clickjacking. DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    "referrer-policy": "Controls how much referrer data leaves your site.",
    "permissions-policy": "Turns off unused browser features (camera, mic, geolocation).",
    "cross-origin-opener-policy": "Isolates your browsing context from other origins.",
}


@dataclass
class HeaderReport:
    present: list[str]
    missing: list[str]
    notes: dict[str, str]
    score: int

    def to_dict(self) -> dict:
        return asdict(self)


def parse_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip():
            if headers:
                break
            continue
        if ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def score_response_file(path: str | Path) -> HeaderReport:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    headers = parse_headers(text)
    present = [name for name in EXPECTED if name in headers]
    missing = [name for name in EXPECTED if name not in headers]
    score = int(round(100 * len(present) / len(EXPECTED)))
    return HeaderReport(present=present, missing=missing, notes=EXPECTED, score=score)
