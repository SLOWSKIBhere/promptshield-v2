"""Adapters from existing PromptShield and Promptfoo result shapes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from models import RiskLevel, ScanResult

from .models import NormalizedFinding, ToolError, ToolRunResult
from .redaction import redact_evidence


def _text(value: object, *, fallback: str, limit: int) -> str:
    cleaned = redact_evidence(value, max_chars=limit)
    return cleaned or fallback


def normalize_promptshield_scan(scan: ScanResult) -> list[NormalizedFinding]:
    """Convert exploited runtime results without changing legacy score semantics."""
    findings: list[NormalizedFinding] = []
    for result in scan.findings:
        if not result.is_exploited:
            continue
        findings.append(NormalizedFinding(
            source="promptshield_runtime",
            risk_id=result.owasp_ref,
            title=result.attack_name,
            severity=result.severity,
            confidence=result.confidence,
            file=None,
            line=None,
            rule=result.attack_id,
            description=_text(
                result.judge_reasoning,
                fallback="The existing PromptShield scan marked this case as exploited.",
                limit=1_000,
            ),
            remediation=_text(
                result.remediation,
                fallback="Review the affected feature and add a tested application-layer control.",
                limit=1_000,
            ),
            redacted_evidence=redact_evidence(result.model_response),
        ))
    return findings


def _schema_rows(payload: Mapping[str, Any]) -> list[object] | ToolError:
    version = payload.get("version")
    result_container: object = payload.get("results")
    if isinstance(result_container, Mapping):
        version = result_container.get("version", version)
        result_container = result_container.get("results")
    if version != 3:
        return ToolError(
            code="unsupported_schema",
            message="Promptfoo output did not use supported JSON schema version 3.",
        )
    if not isinstance(result_container, list):
        return ToolError(
            code="invalid_json",
            message="Promptfoo output did not contain a valid result list.",
        )
    return result_container


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _row_error(row: Mapping[str, Any]) -> bool:
    grading = _mapping(row.get("gradingResult"))
    response = _mapping(row.get("response"))
    return bool(
        row.get("error")
        or row.get("failureReason") in {2, "error", "ERROR"}
        or response.get("error")
        or grading.get("error")
        or grading.get("graderError")
    )


def _row_passed(row: Mapping[str, Any]) -> bool | None:
    grading = _mapping(row.get("gradingResult"))
    if isinstance(row.get("success"), bool):
        return bool(row["success"])
    if isinstance(grading.get("pass"), bool):
        return bool(grading["pass"])
    return None


def _finding_from_promptfoo(row: Mapping[str, Any]) -> NormalizedFinding:
    test_case = _mapping(row.get("testCase"))
    metadata = _mapping(test_case.get("metadata")) or _mapping(row.get("metadata"))
    grading = _mapping(row.get("gradingResult"))
    response = _mapping(row.get("response"))
    required = {
        "risk_id",
        "title",
        "severity",
        "confidence",
        "rule",
        "description",
        "remediation",
    }
    if not required.issubset(metadata):
        raise ValueError("Promptfoo test metadata is incomplete")
    evidence = response.get("output", "")
    reason = grading.get("reason")
    if reason:
        evidence = f"{evidence} Assertion: {reason}"
    return NormalizedFinding(
        source="promptfoo",
        risk_id=metadata["risk_id"],
        title=metadata["title"],
        severity=RiskLevel(metadata["severity"]),
        confidence=metadata["confidence"],
        file=None,
        line=None,
        rule=metadata["rule"],
        description=metadata["description"],
        remediation=metadata["remediation"],
        redacted_evidence=redact_evidence(evidence),
    )


def normalize_promptfoo(payload: Mapping[str, Any]) -> ToolRunResult:
    """Normalize supported Promptfoo v3 output or return a structured run error."""
    rows = _schema_rows(payload)
    if isinstance(rows, ToolError):
        return ToolRunResult(errors=[rows])
    if not rows:
        return ToolRunResult(errors=[ToolError(
            code="no_tests_executed",
            message="Promptfoo completed without executing any tests.",
        )])

    findings: list[NormalizedFinding] = []
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            return ToolRunResult(errors=[ToolError(
                code="invalid_json",
                message="Promptfoo output contained an invalid result entry.",
            )])
        if _row_error(raw_row):
            return ToolRunResult(
                errors=[ToolError(
                    code="evaluation_error",
                    message="Promptfoo reported a transport or evaluator error.",
                )],
                tests_executed=len(rows),
            )
        passed = _row_passed(raw_row)
        if passed is None:
            return ToolRunResult(
                errors=[ToolError(
                    code="evaluation_error",
                    message="Promptfoo did not report a deterministic assertion outcome.",
                )],
                tests_executed=len(rows),
            )
        if not passed:
            try:
                findings.append(_finding_from_promptfoo(raw_row))
            except (TypeError, ValueError):
                return ToolRunResult(
                    errors=[ToolError(
                        code="invalid_json",
                        message="Promptfoo output contained invalid finding metadata.",
                    )],
                    tests_executed=len(rows),
                )
    return ToolRunResult(findings=findings, tests_executed=len(rows))
