"""Secret patterns recognised by log-redactor.

Each pattern is a (kind, compiled-regex) pair.  The regex must contain a
single capture group around the *secret portion* when the surrounding text
(like ``Bearer`` or ``token=``) should be preserved; otherwise the whole
match is the secret and the mask replaces it entirely.

All fixtures used in tests and demos are synthetic — they look real but
are randomly generated and inert.
"""

from __future__ import annotations

import re

Pattern = tuple[str, re.Pattern[str]]

#: (kind, regex) — keep the list ordered from most specific to most generic
#: so overlapping detectors resolve deterministically.
PATTERNS: list[Pattern] = [
    (
        "AWS_ACCESS_KEY_ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        re.compile(
            r"(?i)\baws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\b\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|"
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b"
        ),
    ),
    (
        "OPENAI_API_KEY",
        re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{20,})\b"),
    ),
    (
        "ANTHROPIC_API_KEY",
        re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{20,})\b"),
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,}(?:-[A-Za-z0-9\-]{10,})*)\b"),
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ),
    (
        "DISCORD_WEBHOOK",
        re.compile(
            r"\b(https://discord(?:app)?\.com/api/webhooks/[0-9]{15,}/[A-Za-z0-9_\-]{50,})\b"
        ),
    ),
    (
        "NPM_TOKEN",
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
    ),
    (
        "JWT",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,})\b"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"\bBearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})"),
    ),
    (
        "BASIC_AUTH",
        re.compile(r"\bBasic\s+([A-Za-z0-9+/]{20,}={0,2})"),
    ),
    (
        "GENERIC_ASSIGNMENT",
        re.compile(
            r"(?i)\b((?:api[_-]?key|secret|token|passwd|password|auth[_-]?token|"
            r"access[_-]?token|client[_-]?secret|private[_-]?key)[\"'\]]?\s*[:=]\s*)"
            r"['\"]?([A-Za-z0-9\-_+/=.:@]{12,})['\"]?"
        ),
    ),
]


def iter_matches(text: str):
    """Yield ``(kind, start, end)`` for every secret-shaped match in *text*.

    Overlapping matches from different patterns are deduplicated: the
    longest match wins at any given position.
    """
    spans: list[tuple[str, int, int]] = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            # If the pattern captures the secret in group 2 (prefix preserved),
            # redact only the secret group; otherwise redact the whole match.
            if m.lastindex and m.lastindex >= 2:
                start, end = m.start(2), m.end(2)
            elif m.lastindex == 1:
                start, end = m.start(1), m.end(1)
            else:
                start, end = m.start(0), m.end(0)
            spans.append((kind, start, end))

    # Sort by start, then longest first, and drop any span fully covered by
    # an earlier (longer or equal) span.
    spans.sort(key=lambda s: (s[1], -(s[2] - s[1])))
    kept: list[tuple[str, int, int]] = []
    for kind, start, end in spans:
        if any(start >= ks and end <= ke for _, ks, ke in kept):
            continue
        kept.append((kind, start, end))
    kept.sort(key=lambda s: s[1])
    return kept
