"""Stable assembly and JSON serialization for normalized scan results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone

from models import RiskLevel

from .models import NormalizedFinding, ReportSummary, ScanDiagnostic, ToolError, UnifiedReport


def _finding_key(finding: NormalizedFinding) -> tuple[object, ...]:
    return (finding.source, finding.risk_id, finding.rule, finding.file, finding.line)


def _finding_sort_key(finding: NormalizedFinding) -> tuple[object, ...]:
    severity_order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4,
    }
    return (
        severity_order[finding.severity],
        finding.source,
        finding.file or "",
        finding.line or 0,
        finding.risk_id,
        finding.rule,
    )


def build_report(
    finding_groups: Iterable[Iterable[NormalizedFinding]],
    *,
    tool_errors: Iterable[ToolError] = (),
    diagnostics: Iterable[ScanDiagnostic] = (),
    generated_at: datetime | None = None,
) -> UnifiedReport:
    """Deduplicate exact finding identities and build counts without a grade."""
    unique: dict[tuple[object, ...], NormalizedFinding] = {}
    for group in finding_groups:
        for finding in group:
            unique.setdefault(_finding_key(finding), finding)
    findings = sorted(unique.values(), key=_finding_sort_key)
    errors = sorted(list(tool_errors), key=lambda item: (item.tool, item.code, item.exit_code or 0))
    diagnostic_list = sorted(
        list(diagnostics),
        key=lambda item: (item.file or "", item.line or 0, item.code),
    )

    severity_counts = Counter(finding.severity.value for finding in findings)
    source_counts = Counter(finding.source for finding in findings)
    summary = ReportSummary(
        finding_count=len(findings),
        by_severity={level.value: severity_counts[level.value] for level in RiskLevel},
        by_source=dict(sorted(source_counts.items())),
        tool_error_count=len(errors),
        diagnostic_count=len(diagnostic_list),
    )
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return UnifiedReport(
        generated_at=timestamp,
        findings=findings,
        tool_errors=errors,
        diagnostics=diagnostic_list,
        summary=summary,
    )


def report_json(report: UnifiedReport) -> str:
    return report.model_dump_json(indent=2) + "\n"
