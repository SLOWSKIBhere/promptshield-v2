"""Strict normalized contracts for local defensive security scans."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from models import RiskLevel

from .redaction import redact_evidence


FindingSource = Literal["static", "promptfoo", "promptshield_runtime", "web_top10"]
ToolErrorCode = Literal[
    "not_installed",
    "unauthorized_target",
    "timeout",
    "nonzero_exit",
    "output_too_large",
    "invalid_json",
    "unsupported_schema",
    "empty_result",
    "no_tests_executed",
    "evaluation_error",
]

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _validate_relative_posix_path(value: str | None) -> str | None:
    if value is None:
        return None
    if value in {"", ".", ".."} or "\\" in value or "\x00" in value or _WINDOWS_DRIVE.match(value):
        raise ValueError("file must be a normalized relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError("file must be a normalized relative POSIX path")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class NormalizedFinding(StrictModel):
    source: FindingSource
    risk_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    severity: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    file: str | None = Field(default=None, max_length=500)
    line: int | None = Field(default=None, ge=1)
    rule: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1_000)
    remediation: str = Field(min_length=1, max_length=1_000)
    redacted_evidence: str = Field(default="", max_length=500)

    _relative_path = field_validator("file")(_validate_relative_posix_path)

    @field_validator("redacted_evidence")
    @classmethod
    def sanitize_evidence(cls, value: str) -> str:
        return redact_evidence(value)

    @model_validator(mode="after")
    def line_requires_file(self) -> "NormalizedFinding":
        if self.line is not None and self.file is None:
            raise ValueError("line requires file")
        return self


class ToolError(StrictModel):
    tool: Literal["promptfoo"] = "promptfoo"
    code: ToolErrorCode
    message: str = Field(min_length=1, max_length=300)
    exit_code: int | None = None


class ScanDiagnostic(StrictModel):
    code: Literal[
        "invalid_root",
        "file_limit_reached",
        "file_too_large",
        "total_bytes_exceeded",
        "read_error",
        "syntax_error",
        "skipped_symlink",
        "invalid_promptshield_json",
    ]
    message: str = Field(min_length=1, max_length=300)
    file: str | None = Field(default=None, max_length=500)
    line: int | None = Field(default=None, ge=1)

    _relative_path = field_validator("file")(_validate_relative_posix_path)

    @model_validator(mode="after")
    def line_requires_file(self) -> "ScanDiagnostic":
        if self.line is not None and self.file is None:
            raise ValueError("line requires file")
        return self


class StaticScanResult(StrictModel):
    findings: list[NormalizedFinding] = Field(default_factory=list)
    diagnostics: list[ScanDiagnostic] = Field(default_factory=list)
    files_scanned: int = Field(default=0, ge=0)
    bytes_scanned: int = Field(default=0, ge=0)


class ToolRunResult(StrictModel):
    tool: Literal["promptfoo"] = "promptfoo"
    findings: list[NormalizedFinding] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)
    tests_executed: int = Field(default=0, ge=0)


class ReportSummary(StrictModel):
    finding_count: int = Field(ge=0)
    by_severity: dict[str, int]
    by_source: dict[str, int]
    tool_error_count: int = Field(ge=0)
    diagnostic_count: int = Field(ge=0)


class UnifiedReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime
    findings: list[NormalizedFinding] = Field(default_factory=list)
    tool_errors: list[ToolError] = Field(default_factory=list)
    diagnostics: list[ScanDiagnostic] = Field(default_factory=list)
    summary: ReportSummary
