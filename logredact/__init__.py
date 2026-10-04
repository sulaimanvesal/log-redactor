"""log-redactor — scrub leaked secrets from LLM/agent logs and CI output."""

from .redact import Finding, redact, redact_stream, scan

__all__ = ["Finding", "redact", "redact_stream", "scan"]
__version__ = "0.1.0"
