#!/usr/bin/env python3
"""Runnable demo: redact a synthetic agent log (zero API keys needed).

Shows the raw log, the redacted log, and a JSON findings report.
Every credential in examples/agent.log is fake and inert.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from logredact import redact, scan  # noqa: E402

LOG = Path(__file__).resolve().parent / "examples" / "agent.log"


def main() -> int:
    raw = LOG.read_text(encoding="utf-8")
    findings = scan(raw)
    redacted, _ = redact(raw)

    print("=" * 72)
    print("RAW LOG (synthetic secrets)")
    print("=" * 72)
    print(raw)
    print("=" * 72)
    print("REDACTED LOG")
    print("=" * 72)
    print(redacted)
    print("=" * 72)
    print(f"FINDINGS: {len(findings)} secret(s) detected")
    print("=" * 72)
    print(json.dumps([f.to_dict() for f in findings], indent=2))

    # Sanity: nothing secret-shaped may survive redaction.
    leftover = scan(redacted)
    assert not leftover, f"redaction incomplete: {leftover}"
    print("\nDemo OK — redacted output contains zero detectable secrets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
