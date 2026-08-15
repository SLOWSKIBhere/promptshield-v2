from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest

import database
import engine
import main
from models import AttackResult, RiskLevel, ScanStatus, ScanTarget


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
        "timeout": main.settings.provider_timeout_seconds,
    }


def test_direct_provider_clients_use_explicit_timeout(monkeypatch):
    anthropic_kwargs = {}
    openai_kwargs = {}

    def fake_anthropic(**kwargs):
        anthropic_kwargs.update(kwargs)
        return object()

    def fake_openai(**kwargs):
        openai_kwargs.update(kwargs)
        return object()

    monkeypatch.setattr(main.settings, "anthropic_api_key", "test-anthropic-key")
    monkeypatch.setattr(main.settings, "openai_api_key", "test-openai-key")
    monkeypatch.setattr(main.anthropic, "AsyncAnthropic", fake_anthropic)
    monkeypatch.setattr(main.openai_lib, "AsyncOpenAI", fake_openai)

    assert main._get_anthropic_client() is not None
    assert main._get_openai_client() is not None
    assert anthropic_kwargs["timeout"] == main.settings.provider_timeout_seconds
    assert openai_kwargs["timeout"] == main.settings.provider_timeout_seconds


def test_valid_scan_creation_returns_202_and_id(client):
    response = client.post("/scans", json=VALID_TARGET)
    assert response.status_code == 202
    assert response.json()["scan_id"]
    assert response.json()["status"] == "running"


def test_scan_name_is_not_written_to_application_logs(client, caplog):
    private_name = "private-scan-label-for-log-regression"
    response = client.post(
        "/scans",
        json={**VALID_TARGET, "scan_name": private_name},
    )
    assert response.status_code == 202
    assert private_name not in caplog.text


def test_submitted_target_api_key_is_never_persisted_or_logged(client, db_path, caplog):
    secret = "target-secret-that-must-not-reach-sqlite"
    response = client.post(
        "/scans",
        json={
            **VALID_TARGET,
            "scan_name": f"Scan label {secret}",
            "feature_description": f"Feature description {secret}",
            "system_prompt": f"You are a safe assistant. Credential: {secret}",
            "endpoint_url": "https://example.com/inference",
            "api_key": secret,
        },
    )
    assert response.status_code == 202
    assert secret not in response.text
    assert secret.encode() not in db_path.read_bytes()
    assert secret not in caplog.text


@pytest.mark.parametrize("categories", [[], ["unknown"], ["prompt_injection", "unknown"]])
def test_invalid_categories_return_422(client, categories):
    response = client.post("/scans", json={**VALID_TARGET, "categories": categories})
    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.parametrize("categories", [
    ["prompt_injection", "prompt_injection"],
    ["prompt_injection"] * 6,
])
def test_duplicate_or_oversized_category_lists_return_422(client, categories):
    response = client.post("/scans", json={**VALID_TARGET, "categories": categories})
    assert response.status_code == 422


def test_validation_error_does_not_reflect_submitted_api_key(client):
    secret = "validation-secret-" + ("x" * 500)
    response = client.post(
        "/scans",
        json={
            **VALID_TARGET,
            "endpoint_url": "https://example.com/inference",
            "api_key": secret,
        },
    )
    assert response.status_code == 422
    assert secret not in response.text
    assert all("input" not in item for item in response.json()["detail"])


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


async def test_background_client_setup_failure_reaches_failed_state(
    scan_factory, monkeypatch, caplog
):
    scan_factory("setup-failure")

    def fail_during_setup():
        raise RuntimeError("internal setup detail")

    monkeypatch.setattr(main, "_get_anthropic_client", fail_during_setup)
    await main._run_scan_background("setup-failure", ScanTarget(**VALID_TARGET))

    scan = database.get_scan("setup-failure")
    assert scan.status == ScanStatus.FAILED
    assert scan.completed_at is not None
    assert scan.failure_reason == "Scan failed: RuntimeError"
    assert "internal setup detail" not in scan.failure_reason
    assert "internal setup detail" not in caplog.text


async def test_reflected_target_key_is_redacted_before_judging_and_persistence(
    scan_factory, db_path, monkeypatch
):
    secret = "ZXQ9-reflected-key-that-must-not-be-persisted"
    attack = engine.AttackPrompt(
        id="a",
        category="prompt_injection",
        name="Reflection check",
        description="Synthetic regression case",
        payload="ordinary test input",
        severity=RiskLevel.HIGH,
        owasp_ref="LLM01:2026",
        expected_safe_behavior="Return an ordinary response",
    )

    class FakeResponse:
        status_code = 200
        headers = {}

        def raise_for_status(self):
            return None

        def json(self):
            return {"diagnostic": ("x" * 1980) + secret}

        async def aiter_bytes(self, chunk_size=None):
            del chunk_size
            yield json.dumps(self.json()).encode()

    class FakeStreamContext:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, *args):
            return None

    class FakeAsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def stream(self, *args, **kwargs):
            return FakeStreamContext()

    async def no_sleep(_delay):
        return None

    scan_factory("reflected-key")
    monkeypatch.setattr(main, "_get_anthropic_client", lambda: None)
    monkeypatch.setattr(main, "_get_openai_client", lambda: None)
    monkeypatch.setattr(main, "_get_groq_client", lambda: None)
    monkeypatch.setattr(main.settings, "judge_provider", "heuristic")
    monkeypatch.setattr(engine, "load_attack_library", lambda categories: [attack])
    monkeypatch.setattr(engine, "_is_safe_url", lambda url: (True, ""))
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(engine.asyncio, "sleep", no_sleep)

    target = ScanTarget(
        **VALID_TARGET,
        endpoint_url="https://example.com/inference",
        api_key=secret,
    )
    await main._run_scan_background("reflected-key", target)

    scan = database.get_scan("reflected-key")
    assert scan.status == ScanStatus.COMPLETED
    assert secret not in scan.model_dump_json()
    assert secret[:4] not in scan.model_dump_json()
    assert secret.encode() not in db_path.read_bytes()
    assert secret[:4].encode() not in db_path.read_bytes()
    assert secret not in main.generate_html_report(scan)
