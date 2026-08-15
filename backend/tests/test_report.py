from __future__ import annotations

from datetime import datetime, timezone

from models import AttackResult, RiskLevel, ScanResult, ScanStatus
from report import generate_html_report


def test_report_escapes_untrusted_text_and_includes_scope_disclaimer():
    markup = "<em data-check='untrusted'>sample & value</em>"
    finding = AttackResult(
        attack_id="a",
        attack_name=markup,
        category="prompt_injection",
        severity=RiskLevel.HIGH,
        owasp_ref="LLM01:2026",
        payload=markup,
        model_response=markup,
        is_exploited=True,
        confidence=0.9,
        judge_reasoning=markup,
        remediation=markup,
    )
    scan = ScanResult(
        scan_id="scan-1",
        scan_name=markup,
        feature_description=markup,
        system_prompt_preview=markup,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        status=ScanStatus.COMPLETED,
        findings=[finding],
        total_attacks=1,
        exploited_count=1,
        summary=markup,
    )

    report = generate_html_report(scan)

    assert markup not in report
    assert "&lt;em data-check=&#x27;untrusted&#x27;&gt;sample &amp; value&lt;/em&gt;" in report
    assert "not a security certification" in report
    assert "OWASP GenAI LLM Top 10 (2026)" in report
