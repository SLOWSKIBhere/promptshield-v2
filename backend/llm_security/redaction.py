"""Deterministic, bounded redaction for evidence leaving scanner boundaries."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable


REDACTED = "[REDACTED]"
MAX_EVIDENCE_CHARS = 500

_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password)\b"
    r"\s*[:=]\s*(?:[\"'])?[^\s,;}'\"]+"
)
_BEARER_SECRET = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b"),
)


def contains_credential(value: str) -> bool:
    """Return whether a literal contains a conservative credential signature."""
    return bool(
        _ASSIGNMENT_SECRET.search(value)
        or _BEARER_SECRET.search(value)
        or any(pattern.search(value) for pattern in _TOKEN_PATTERNS)
    )


def _redact_exact(value: str, secret: str) -> str:
    if not secret or secret not in value:
        return value
    if secret in REDACTED:
        return ""
    redacted = value.replace(secret, REDACTED)
    return redacted if secret not in redacted else ""


def redact_evidence(
    value: object,
    *,
    exact_secrets: Iterable[str] = (),
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> str:
    """Remove credential signatures and controls before bounding a one-line excerpt."""
    text = _ANSI_ESCAPE.sub("", str(value))
    for secret in sorted({item for item in exact_secrets if item}, key=len, reverse=True):
        text = _redact_exact(text, secret)
    text = _ASSIGNMENT_SECRET.sub(lambda match: f"{match.group(1)}={REDACTED}", text)
    text = _BEARER_SECRET.sub(f"Bearer {REDACTED}", text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)

    normalized = []
    for char in text:
        category = unicodedata.category(char)
        if char.isspace():
            normalized.append(" ")
        elif category not in {"Cc", "Cf"}:
            normalized.append(char)
    compact = re.sub(r" +", " ", "".join(normalized)).strip()
    return compact[:max_chars]
