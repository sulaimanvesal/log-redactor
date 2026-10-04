"""Core redaction engine: scan text, replace secrets with typed masks."""

from __future__ import annotations

from dataclasses import dataclass

from .patterns import iter_matches

DEFAULT_MASK = "[REDACTED:{kind}]"


@dataclass
class Finding:
    """One detected secret."""

    kind: str
    line: int  # 1-based
    column: int  # 1-based
    length: int
    preview: str  # first 4 chars of the secret, then ellipsis — never the secret

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "line": self.line,
            "column": self.column,
            "length": self.length,
            "preview": self.preview,
        }


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - text.rfind("\n", 0, offset)
    return line, col


def scan(text: str) -> list[Finding]:
    """Return a list of findings without modifying *text*."""
    findings: list[Finding] = []
    for kind, start, end in iter_matches(text):
        secret = text[start:end]
        line, col = _line_col(text, start)
        findings.append(
            Finding(
                kind=kind,
                line=line,
                column=col,
                length=end - start,
                preview=secret[:4] + "…" if len(secret) > 4 else "…" * len(secret),
            )
        )
    return findings


def redact(text: str, mask: str = DEFAULT_MASK) -> tuple[str, list[Finding]]:
    """Replace every detected secret with ``mask``.

    ``mask`` may contain ``{kind}`` which is replaced with the finding kind,
    e.g. ``[REDACTED:OPENAI_API_KEY]``.

    Returns ``(redacted_text, findings)``.
    """
    findings = scan(text)
    if not findings:
        return text, findings

    spans = iter_matches(text)
    parts: list[str] = []
    cursor = 0
    for kind, start, end in spans:
        parts.append(text[cursor:start])
        parts.append(mask.format(kind=kind))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), findings


def redact_stream(lines, mask: str = DEFAULT_MASK):
    """Yield redacted lines plus a running finding count (for huge logs)."""
    total = 0
    for line in lines:
        redacted, findings = redact(line, mask)
        total += len(findings)
        yield redacted
    return total
