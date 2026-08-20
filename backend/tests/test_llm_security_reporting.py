from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from llm_security.models import NormalizedFinding, ScanDiagnostic, ToolError, UnifiedReport
from llm_security.models import ToolRunResult
from llm_security import __main__ as llm_cli
from llm_security.normalizers import normalize_promptshield_scan
from llm_security.reporting import build_report, report_json
from models import AttackResult, RiskLevel, ScanResult, ScanStatus


def _finding(**overrides):
    values = {
        "source": "static",
        "risk_id": "LLM06:2026",
        "title": "Missing output bound",
        "severity": RiskLevel.MEDIUM,
        "confidence": 0.75,
        "file": "src/app.py",
        "line": 10,
        "rule": "PS-LLM06-001",
        "description": "Generation is not explicitly bounded.",
        "remediation": "Set a provider-supported token limit.",
        "redacted_evidence": "client.responses.create(...) ",
    }
    values.update(overrides)
    return NormalizedFinding(**values)


def _runtime_scan():
    common = {
        "category": "prompt_injection",
        "severity": RiskLevel.HIGH,
        "owasp_ref": "LLM01:2026",
        "payload": "test",
        "model_response": "API_KEY=sk-secretvalue123",
        "confidence": 0.9,
        "judge_reasoning": "The case was accepted.",
        "remediation": "Separate data and instructions.",
    }
    return ScanResult(
        scan_id="scan-1",
        scan_name="Existing scan",
        feature_description="Existing feature description",
        system_prompt_preview="You are a test assistant.",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        status=ScanStatus.COMPLETED,
        overall_score=82.5,
        letter_grade="B",
        findings=[
            AttackResult(
                attack_id="PI-001",
                attack_name="Direct override",
                is_exploited=True,
                **common,
            ),
            AttackResult(
                attack_id="PI-002",
                attack_name="Safe refusal",
                is_exploited=False,
                **common,
            ),
        ],
    )


def test_only_exploited_runtime_results_are_mapped_without_score_changes():
    scan = _runtime_scan()

    findings = normalize_promptshield_scan(scan)

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.source, finding.risk_id, finding.title, finding.rule) == (
        "promptshield_runtime",
        "LLM01:2026",
        "Direct override",
        "PI-001",
    )
    assert finding.file is None and finding.line is None
    assert "sk-secretvalue123" not in finding.redacted_evidence
    assert scan.overall_score == 82.5 and scan.letter_grade == "B"


@pytest.mark.parametrize(
    "overrides",
    [
        {"confidence": float("nan")},
        {"confidence": 1.01},
        {"severity": "urgent"},
        {"file": "/etc/passwd"},
        {"file": "src/../secret.py"},
        {"file": "C:\\secret.py"},
        {"description": "x" * 1_001},
    ],
)
def test_normalized_finding_rejects_invalid_values(overrides):
    with pytest.raises(ValidationError):
        _finding(**overrides)


def test_normalized_finding_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        NormalizedFinding(**_finding().model_dump(), unexpected=True)


def test_normalized_finding_sanitizes_evidence_at_the_contract_boundary():
    finding = _finding(redacted_evidence="API_KEY=sk-contractsecret123\x00")

    assert "sk-contractsecret123" not in finding.redacted_evidence
    assert "\x00" not in finding.redacted_evidence


def test_report_deduplicates_exact_keys_sorts_and_excludes_errors_from_counts():
    duplicate = _finding(title="First instance")
    replacement = _finding(title="Second instance")
    critical = _finding(
        risk_id="LLM10:2026",
        title="Execution sink",
        severity=RiskLevel.CRITICAL,
        confidence=0.95,
        file="src/z.py",
        line=2,
        rule="PS-LLM10-001",
    )
    timestamp = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)

    report = build_report(
        [[duplicate, critical], [replacement]],
        tool_errors=[ToolError(code="timeout", message="Promptfoo timed out.")],
        diagnostics=[ScanDiagnostic(code="syntax_error", message="Could not parse.", file="bad.py", line=1)],
        generated_at=timestamp,
    )

    assert [item.title for item in report.findings] == ["Execution sink", "First instance"]
    assert report.generated_at == timestamp
    assert report.summary.finding_count == 2
    assert report.summary.by_severity["critical"] == 1
    assert report.summary.by_severity["medium"] == 1
    assert sum(report.summary.by_severity.values()) == 2
    assert report.summary.by_source == {"static": 2}
    assert report.summary.tool_error_count == 1
    assert report.summary.diagnostic_count == 1
    assert "grade" not in report.model_dump()


def test_json_round_trip_is_stable_and_evidence_is_bounded():
    report = build_report(
        [[_finding(redacted_evidence="x" * 500)]],
        generated_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    serialized = report_json(report)
    restored = UnifiedReport.model_validate_json(serialized)

    assert restored == report
    assert serialized.endswith("\n")
    assert json.loads(serialized)["schema_version"] == "1.0"


def test_cli_defaults_to_stdout_and_findings_do_not_fail_the_run(tmp_path, capsys):
    (tmp_path / "unsafe.py").write_text(
        "client.responses.create(model='x', input='x')\n",
        encoding="utf-8",
    )

    exit_code = llm_cli.main(["scan", "--source-root", str(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["summary"]["finding_count"] == 1
    assert payload["findings"][0]["rule"] == "PS-LLM06-001"


def test_cli_returns_two_with_structured_tool_error(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        llm_cli,
        "run_promptfoo",
        lambda: ToolRunResult(errors=[ToolError(code="timeout", message="Promptfoo timed out.")]),
    )

    exit_code = llm_cli.main([
        "scan",
        "--source-root",
        str(tmp_path),
        "--promptfoo-local",
    ])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["findings"] == []
    assert payload["tool_errors"][0]["code"] == "timeout"
