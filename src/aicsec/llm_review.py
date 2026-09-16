"""Build a constrained prompt for LLM-assisted secure code review.

Default mode only prints the prompt. If OPENAI_API_KEY is set, an optional
call is made. The prompt forbids exploit writing and asks for fixes only.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

SYSTEM_PROMPT = """You are a senior application-security reviewer.
Review the supplied source for vulnerabilities that a defender should fix.

Rules:
- Only discuss issues present in this snippet.
- Recommend secure fixes and safer APIs.
- Do not write exploit PoCs, payloads, or attack instructions.
- Do not invent files or systems that are not in the snippet.
- Rate each finding: critical, high, medium, low, info.
- Return JSON with keys: summary, findings[{title,severity,cwe,why,fix}].
"""


def build_prompt(source: str, filename: str) -> str:
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"File: {filename}\n"
        f"```\n{source[:12000]}\n```\n"
    )


def review_file(path: str | Path, call_api: bool = False) -> dict:
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8", errors="ignore")
    prompt = build_prompt(source, file_path.name)
    result: dict = {"filename": file_path.name, "prompt": prompt, "model_json": None}

    if not call_api:
        return result

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        result["error"] = "OPENAI_API_KEY is not set; printed prompt only."
        return result

    payload = {
        "model": os.environ.get("AICSEC_MODEL", "gpt-4o-mini"),
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"File: {file_path.name}\n```\n{source[:12000]}\n```"},
        ],
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode("utf-8"))
    result["model_json"] = body["choices"][0]["message"]["content"]
    return result
