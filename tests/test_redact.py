"""Tests for the redaction engine."""

from logredact import redact, scan


def test_redact_replaces_with_typed_mask():
    text = "using sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs for the call"
    redacted, findings = redact(text)
    assert redacted == "using [REDACTED:OPENAI_API_KEY] for the call"
    assert len(findings) == 1
    assert findings[0].kind == "OPENAI_API_KEY"


def test_redact_preserves_line_structure():
    text = (
        "line one is clean\n"
        "line two has sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs inside\n"
        "line three is clean\n"
    )
    redacted, findings = redact(text)
    assert redacted.splitlines() == [
        "line one is clean",
        "line two has [REDACTED:OPENAI_API_KEY] inside",
        "line three is clean",
    ]
    assert findings[0].line == 2


def test_redact_is_idempotent():
    text = "token ghp_9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRsTuV here"
    once, _ = redact(text)
    twice, findings2 = redact(once)
    assert once == twice
    assert findings2 == []


def test_redact_clean_text_unchanged():
    text = "nothing to see here, move along"
    redacted, findings = redact(text)
    assert redacted == text
    assert findings == []


def test_multiple_secrets_one_line():
    text = (
        "openai sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs "
        # Stripe fixture assembled in pieces (see test_patterns.py note).
        "and stripe " "sk_live_" "9XkL2mQvR7tYwZ1aBcDeFgHiJkL" " done"
    )
    redacted, findings = redact(text)
    assert redacted == (
        "openai [REDACTED:OPENAI_API_KEY] and stripe [REDACTED:STRIPE_KEY] done"
    )
    assert {f.kind for f in findings} == {"OPENAI_API_KEY", "STRIPE_KEY"}


def test_custom_mask_template():
    text = "key=sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs"
    redacted, _ = redact(text, mask="***{kind}***")
    assert redacted == "key=***OPENAI_API_KEY***"


def test_finding_preview_never_contains_secret():
    secret = "sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs"
    (finding,) = scan(f"call with {secret} now")
    assert secret not in finding.preview
    assert len(secret) > len(finding.preview.replace("…", ""))


def test_scan_reports_line_and_column():
    text = "ab\ncd sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs\n"
    (finding,) = scan(text)
    assert (finding.line, finding.column) == (2, 4)
    assert finding.length == len("sk-9XkL2mQvR7tYwZ1aBcDeFgHiJkLmNoPqRs")
