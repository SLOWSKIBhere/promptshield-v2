from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import database
import main
from models import AttackResult, RiskLevel, ScanStatus


VALID_TARGET = {
    "scan_name": "Contract test",
    "system_prompt": "You are a safe and helpful support assistant.",
    "feature_description": "Customer support assistant",
    "categories": ["prompt_injection"],
}


def test_health_and_configuration_flags(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["allow_private_targets"] is False
    assert body["auth_enabled"] is False
    assert body["judge_provider"] == main.settings.judge_provider
    assert body["target_provider"] == main.settings.target_provider
    assert body["groq_configured"] is bool(main.settings.groq_api_key)


def test_groq_client_uses_openai_compatible_base_url(monkeypatch):
    captured = {}

    def fake_client(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(main.settings, "groq_api_key", "test-groq-key")
    monkeypatch.setattr(main.settings, "groq_base_url", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(main.openai_lib, "AsyncOpenAI", fake_client)

    assert main._get_groq_client() is not None
    assert captured == {
        "api_key": "test-groq-key",
        "base_url": "https://api.groq.com/openai/v1",
    }


def test_valid_scan_creation_returns_202_and_id(client):
    response = client.post("/scans", json=VALID_TARGET)
    assert response.status_code == 202
    assert response.json()["scan_id"]
    assert response.json()["status"] == "running"


def test_submitted_target_api_key_is_never_persisted(client, db_path):
    secret = "target-secret-that-must-not-reach-sqlite"
    response = client.post(
        "/scans",
        json={
            **VALID_TARGET,
            "endpoint_url": "https://example.com/inference",
            "api_key": secret,
        },
    )
    assert response.status_code == 202
    assert secret.encode() not in db_path.read_bytes()


@pytest.mark.parametrize("categories", [[], ["unknown"], ["prompt_injection", "unknown"]])
def test_invalid_categories_return_422(client, categories):
    response = client.post("/scans", json={**VALID_TARGET, "categories": categories})
    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.parametrize("method,path", [
    ("get", "/scans/missing"),
    ("get", "/scans/missing/progress"),
    ("get", "/scans/missing/report"),
    ("delete", "/scans/missing"),
])
def test_missing_scan_routes_return_404(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 404
    assert response.json()["detail"]


def test_running_results_and_progress_are_not_cached(client, scan_factory):
    scan_factory(total_attacks=5, current_attack_index=2, current_attack_name="Attack two")
    result = client.get("/scans/scan-1")
    progress = client.get("/scans/scan-1/progress")
    assert result.headers["cache-control"] == "no-store"
    assert progress.headers["cache-control"] == "no-store"
    assert progress.json() == {
        "scan_id": "scan-1", "status": "running", "current": 2, "total": 5,
        "current_attack": "Attack two", "failure_reason": None,
    }


def test_history_order_and_summary_counts(client, scan_factory):
    finding = AttackResult(
        attack_id="a", attack_name="A", category="prompt_injection",
        severity=RiskLevel.CRITICAL, owasp_ref="LLM01", payload="x",
        model_response="bad", is_exploited=True, confidence=.9,
        judge_reasoning="exploited", remediation="fix",
    )
    old = datetime.now(timezone.utc) - timedelta(days=1)
    scan_factory("old", ScanStatus.COMPLETED, started_at=old, findings=[finding],
                 total_attacks=1, exploited_count=1)
    scan_factory("new", ScanStatus.COMPLETED, total_attacks=0)
    body = client.get("/scans").json()
    assert [item["scan_id"] for item in body] == ["new", "old"]
    assert body[1]["critical_count"] == 1
    assert body[1]["exploited_count"] == 1


def test_delete_removes_exactly_one(client, scan_factory):
    scan_factory("one")
    scan_factory("two")
    assert client.delete("/scans/one").json() == {"deleted": "one"}
    assert database.get_scan("one") is None
    assert database.get_scan("two") is not None


def test_report_requires_completion_and_then_returns_html(client, scan_factory):
    scan_factory("report")
    assert client.get("/scans/report/report").status_code == 400
    scan = database.get_scan("report")
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    database.save_scan(scan)
    response = client.get("/scans/report/report")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PromptShield" in response.text
