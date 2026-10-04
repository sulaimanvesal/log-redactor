"""log-redactor: scrub leaked secrets from LLM/agent logs and CI output.

Reads text files (or stdin), detects ~15 kinds of leaked credentials, and
rewrites the text with typed masks like ``[REDACTED:OPENAI_API_KEY]``.

Examples
--------
    # Redact a log file to stdout
    log-redactor agent.log

    # Redact in place
    log-redactor --in-place agent.log debug.log

    # CI gate: exit 1 if any secret is present, without printing the log
    log-redactor --check agent.log

    # JSON report of findings to stderr
    some-agent 2>&1 | log-redactor --json-report
"""

from __future__ import annotations

import argparse
import json
import sys

from .redact import DEFAULT_MASK, redact, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-redactor",
        description="Redact leaked secrets from logs, transcripts and CI output.",
    )
    p.add_argument(
        "paths",
        nargs="*",
        help="Files to process. Reads stdin when omitted or when '-' is given.",
    )
    p.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        help="Rewrite each input file in place instead of printing to stdout.",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any secret is found (prints nothing redacted).",
    )
    p.add_argument(
        "--json-report",
        action="store_true",
        help="Print a JSON findings report to stderr (or stdout with --check).",
    )
    p.add_argument(
        "--mask",
        default=DEFAULT_MASK,
        help="Mask template; {kind} is replaced with the secret kind. "
        'Default: "[REDACTED:{kind}]".',
    )
    return p


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _report(findings, json_report: bool, out) -> None:
    if json_report:
        json.dump([f.to_dict() for f in findings], out, indent=2)
        out.write("\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = args.paths or ["-"]

    if args.check:
        # Check mode: never print log contents, just the report + exit code.
        all_findings = []
        for path in paths:
            all_findings.extend(scan(_read_source(path)))
        _report(all_findings, args.json_report, sys.stdout)
        return 1 if all_findings else 0

    exit_code = 0
    for path in paths:
        original = _read_source(path)
        redacted, findings = redact(original, args.mask)
        if args.in_place:
            if path == "-":
                print("log-redactor: --in-place needs a real file, not stdin",
                      file=sys.stderr)
                return 2
            if redacted != original:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(redacted)
        else:
            sys.stdout.write(redacted)
        _report(findings, args.json_report, sys.stderr)
        if findings:
            print(
                f"log-redactor: redacted {len(findings)} secret(s) "
                f"in {path if path != '-' else 'stdin'}",
                file=sys.stderr,
            )
            exit_code = 0  # redaction succeeded; not a failure
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
