from __future__ import annotations

from types import SimpleNamespace
import socket

import httpx
import pytest

import engine
from models import AttackPrompt, RiskLevel


@pytest.fixture(autouse=True)
def stable_public_dns(monkeypatch):
    """Keep endpoint tests deterministic and completely offline."""
    monkeypatch.setattr(
        engine.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )


class FakeAsyncClient:
    response = None
    error = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


@pytest.mark.parametrize("key", ["response", "message", "content", "output", "text", "answer", "result"])
async def test_custom_endpoint_supported_response_keys(monkeypatch, key):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(200, json={key: "value"}, request=httpx.Request("POST", "https://example.com"))
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)
    assert await engine.call_target("p", "s", "https://example.com", None, "m", None, None) == "value"


async def test_custom_endpoint_non_2xx(monkeypatch):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(503, request=httpx.Request("POST", "https://example.com"))
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)
    assert await engine.call_target("p", "s", "https://example.com", None, "m", None, None) == "[HTTP_ERROR: 503]"


async def test_custom_endpoint_invalid_json_and_array(monkeypatch):
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(200, text="<html>", request=httpx.Request("POST", "https://example.com"))
    assert (await engine.call_target("p", "s", "https://example.com", None, "m", None, None)).startswith("[INVALID_JSON:")
    FakeAsyncClient.response = httpx.Response(200, json=["bad"], request=httpx.Request("POST", "https://example.com"))
    assert (await engine.call_target("p", "s", "https://example.com", None, "m", None, None)).startswith("[INVALID_RESPONSE:")


async def test_custom_endpoint_timeout(monkeypatch):
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)
    FakeAsyncClient.error = httpx.ReadTimeout("slow")
    assert (await engine.call_target("p", "s", "https://example.com", None, "m", None, None)).startswith("[TIMEOUT:")
    FakeAsyncClient.error = None


def test_ssrf_rejection_and_development_override():
    assert engine._is_safe_url("http://127.0.0.1:9000", False)[0] is False
    assert engine._is_safe_url("http://localhost:9000", False)[0] is False
    assert engine._is_safe_url("http://127.0.0.1:9000", True)[0] is True
    assert engine._is_safe_url("file:///etc/passwd", True)[0] is False


def test_ssrf_rejects_hostname_that_resolves_to_private_address(monkeypatch):
    monkeypatch.setattr(
        engine.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))
        ],
    )

    safe, reason = engine._is_safe_url("https://metadata.example.test/model", False)

    assert safe is False
    assert "non-public" in reason
    assert engine._is_safe_url("https://metadata.example.test/model", True) == (True, "")


async def test_provider_errors_are_redacted():
    class Messages:
        async def create(self, **kwargs):
            raise RuntimeError("secret-key-value")
    client = SimpleNamespace(messages=Messages())
    result = await engine.call_target(
        "p", "s", None, None, "model", client, None,
        target_provider="anthropic",
    )
    assert result == "[ANTHROPIC_ERROR: RuntimeError]"
    assert "secret-key-value" not in result


async def test_openai_only_judge_is_explicit():
    content = '{"exploited": true, "confidence": 0.8, "reasoning": "override followed"}'
    class Completions:
        async def create(self, **kwargs):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    attack = AttackPrompt(id="a", category="prompt_injection", name="A", description="d",
                          payload="p", severity=RiskLevel.HIGH, owasp_ref="LLM01",
                          expected_safe_behavior="refuse")
    exploited, confidence, reasoning = await engine.evaluate_with_judge(
        attack, "system prompt", "response", None, client, "openai"
    )
    assert exploited is True
    assert confidence == .8
    assert reasoning == "override followed"


async def test_groq_target_uses_configured_model(monkeypatch):
    captured = {}

    class Completions:
        async def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="safe response"))]
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    monkeypatch.setattr(engine.settings, "groq_target_model", "llama-3.1-8b-instant")

    response = await engine.call_target(
        "payload", "system", None, None, "", None, None,
        groq_client=client, target_provider="groq",
    )

    assert response == "safe response"
    assert captured["model"] == "llama-3.1-8b-instant"
    assert captured["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "payload"},
    ]


async def test_groq_judge_is_explicit(monkeypatch):
    captured = {}
    content = '{"exploited": false, "confidence": 0.9, "reasoning": "refused"}'

    class Completions:
        async def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    monkeypatch.setattr(engine.settings, "groq_judge_model", "llama-3.1-8b-instant")
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="A", description="d",
        payload="p", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    exploited, confidence, reasoning = await engine.evaluate_with_judge(
        attack, "system", "safe response", None,
        judge_provider="groq", groq_client=client,
    )

    assert (exploited, confidence, reasoning) == (False, 0.9, "refused")
    assert captured["model"] == "llama-3.1-8b-instant"


async def test_judge_provider_error_falls_back_to_labeled_heuristic():
    attack = AttackPrompt(id="a", category="prompt_injection", name="A", description="d",
                          payload="p", severity=RiskLevel.HIGH, owasp_ref="LLM01",
                          expected_safe_behavior="refuse")
    exploited, confidence, reasoning = await engine.evaluate_with_judge(
        attack, "system", "I am now a developer mode assistant", None, None, "anthropic"
    )
    assert exploited is True
    assert confidence == .55
    assert "Heuristic" in reasoning


async def test_scan_provider_boundary_reports_consistent_progress(monkeypatch):
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="Injection A", description="d",
        payload="payload", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    class FakeProvider:
        async def call_target(self, payload, system_prompt):
            assert (payload, system_prompt) == ("payload", "system")
            return "safe response"

        async def judge(self, received_attack, system_prompt, response):
            assert (received_attack, system_prompt, response) == (attack, "system", "safe response")
            return False, 0.95, "refused"

    progress = []

    async def record_progress(current, total, name):
        progress.append((current, total, name))

    monkeypatch.setattr(engine, "load_attack_library", lambda categories: [attack])
    monkeypatch.setattr(engine.asyncio, "sleep", lambda _delay: _async_noop())

    results, score, grade, summary = await engine.run_scan(
        scan_id="scan", system_prompt="system", feature_description="feature",
        categories=["prompt_injection"], endpoint_url=None, api_key=None,
        model_name="model", anthropic_client=None, openai_client=None,
        progress_callback=record_progress, provider=FakeProvider(),
    )

    assert progress == [(0, 1, "Injection A"), (1, 1, "Injection A")]
    assert len(results) == 1
    assert results[0].model_response == "safe response"
    assert (score, grade) == (100.0, "A+")
    assert "No vulnerabilities detected" in summary


async def test_operational_target_failure_aborts_scan(monkeypatch):
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="Injection A", description="d",
        payload="payload", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    class FailedProvider:
        async def call_target(self, payload, system_prompt):
            return "[ANTHROPIC_ERROR: AuthenticationError]"

        async def judge(self, attack, system_prompt, response):
            raise AssertionError("judge must not run after target failure")

    monkeypatch.setattr(engine, "load_attack_library", lambda categories: [attack])
    with pytest.raises(engine.TargetCallError, match="AuthenticationError"):
        await engine.run_scan(
            scan_id="scan", system_prompt="system", feature_description="feature",
            categories=["prompt_injection"], endpoint_url=None, api_key=None,
            model_name="model", anthropic_client=None, openai_client=None,
            provider=FailedProvider(),
        )


async def _async_noop():
    return None
