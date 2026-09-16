"""Command line for the defensive toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python -m aicsec.cli` from a clone without installing the package.
SRC = Path(__file__).resolve().parents[1]
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aicsec.header_hygiene import score_response_file
from aicsec.llm_review import review_file
from aicsec.log_anomaly import analyze_log
from aicsec.sast_patterns import scan_path as sast_scan
from aicsec.secret_scan import scan_path as secret_scan


def _print(data, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
        return
    if isinstance(data, list):
        if not data:
            print("No findings.")
            return
        for item in data:
            print(json.dumps(item, indent=2))
            print("---")
        return
    print(json.dumps(data, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aicsec",
        description="Defensive AI cybersecurity helpers for local files you own.",
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_secrets = sub.add_parser("secrets", help="Scan a file or directory for secrets")
    p_secrets.add_argument("path")

    p_sast = sub.add_parser("sast", help="Pattern-based secure-code review")
    p_sast.add_argument("path")

    p_logs = sub.add_parser("logs", help="IsolationForest anomaly hints on a log file")
    p_logs.add_argument("path")

    p_headers = sub.add_parser("headers", help="Score headers in a saved HTTP response")
    p_headers.add_argument("path")

    p_review = sub.add_parser("review", help="Build or run an LLM secure-review prompt")
    p_review.add_argument("path")
    p_review.add_argument(
        "--call-api",
        action="store_true",
        help="Call OpenAI if OPENAI_API_KEY is set",
    )

    args = parser.parse_args(argv)

    if args.cmd == "secrets":
        _print([f.to_dict() for f in secret_scan(args.path)], args.json)
    elif args.cmd == "sast":
        _print([f.to_dict() for f in sast_scan(args.path)], args.json)
    elif args.cmd == "logs":
        _print([f.to_dict() for f in analyze_log(args.path)], args.json)
    elif args.cmd == "headers":
        _print(score_response_file(args.path).to_dict(), args.json)
    elif args.cmd == "review":
        result = review_file(args.path, call_api=args.call_api)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(result["prompt"])
            if result.get("model_json"):
                print("\n--- model ---")
                print(result["model_json"])
            if result.get("error"):
                print(result["error"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
