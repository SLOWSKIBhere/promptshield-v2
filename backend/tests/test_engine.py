from __future__ import annotations

from collections import Counter
import json
from types import SimpleNamespace
import socket

import httpx
import pytest

import engine
from models import AttackCategory, AttackPrompt, RiskLevel


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
    init_kwargs = None
    stream_kwargs = None

    def __init__(self, *args, **kwargs):
        type(self).init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    class _StreamContext:
        def __init__(self, response, error):
            self.response = response
            self.error = error

        async def __aenter__(self):
            if self.error:
                raise self.error
            return self.response

        async def __aexit__(self, *args):
            return None

    def stream(self, *args, **kwargs):
        type(self).stream_kwargs = kwargs
        return self._StreamContext(self.response, self.error)

    async def post(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


@pytest.mark.parametrize("secret", ["API", "KEY", "[", "REDACTED"])
def test_redaction_marker_never_reintroduces_short_submitted_key(secret):
    result = engine._redact_secret(f"before {secret} after", secret)
    assert secret not in result


@pytest.mark.parametrize(("secret", "value"), [
    ("API", "A" + "API" + "PI"),
    ("]x", "]x" + "x"),
])
def test_redaction_drops_text_when_boundaries_recreate_submitted_key(secret, value):
    result = engine._redact_secret(value, secret)
    assert secret not in result


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


async def test_custom_endpoint_redirect_is_not_followed(monkeypatch):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        302,
        headers={"location": "http://127.0.0.1/private"},
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", None, "m", None, None
    )

    assert result == "[HTTP_ERROR: 302]"
    assert FakeAsyncClient.init_kwargs["follow_redirects"] is False
    assert FakeAsyncClient.stream_kwargs["headers"]["Accept-Encoding"] == "identity"


async def test_bearer_key_requires_https_target(monkeypatch):
    FakeAsyncClient.init_kwargs = None
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "http://example.com", "target-key", "m", None, None
    )

    assert result == "[BLOCKED: Bearer authentication requires an HTTPS target]"
    assert FakeAsyncClient.init_kwargs is None


async def test_explicit_private_fixture_still_allows_http_without_bearer(monkeypatch):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        json={"response": "fixture response"},
        request=httpx.Request("POST", "http://127.0.0.1:9000/chat"),
    )
    monkeypatch.setattr(engine.settings, "allow_private_targets", True)
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "http://127.0.0.1:9000/chat", None, "m", None, None
    )

    assert result == "fixture response"


async def test_custom_endpoint_redacts_reflected_bearer_key(monkeypatch):
    secret = "target-key-that-must-not-leave-the-target-boundary"
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        json={"response": f"diagnostic value: {secret}"},
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", secret, "m", None, None
    )

    assert secret not in result
    assert engine._REDACTED_TARGET_KEY in result


async def test_fallback_json_redacts_before_truncation(monkeypatch):
    secret = "ZXQ9-boundary-secret-that-must-not-be-partially-returned"
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        json={"diagnostic": ("x" * 1980) + secret},
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", secret, "m", None, None
    )

    assert secret[:4] not in result
    assert len(result) <= 2000


async def test_fallback_json_redacts_secrets_before_json_escaping(monkeypatch):
    secret = 'quote"and\\backslash-credential'
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        json={secret: {"diagnostic": f"reflected {secret}"}},
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", secret, "m", None, None
    )

    assert secret not in result
    assert json.dumps(secret)[1:-1] not in result
    assert engine._REDACTED_TARGET_KEY in result


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


async def test_custom_endpoint_dns_preflight_has_a_deadline(monkeypatch):
    async def never_resolves(*args, **kwargs):
        await engine.asyncio.Future()

    monkeypatch.setattr(engine.asyncio, "to_thread", never_resolves)
    monkeypatch.setattr(engine, "_TARGET_DNS_TIMEOUT_SECONDS", 0.001)

    result = await engine.call_target(
        "p", "s", "https://example.com", None, "m", None, None
    )

    assert result == "[BLOCKED: Target hostname resolution timed out]"


async def test_custom_endpoint_caps_recognized_response_text(monkeypatch):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        json={"response": "x" * (engine._TARGET_RESPONSE_MAX_CHARS + 100)},
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", None, "m", None, None
    )

    assert len(result) == engine._TARGET_RESPONSE_MAX_CHARS


async def test_custom_endpoint_rejects_oversized_response_body(monkeypatch):
    FakeAsyncClient.error = None
    FakeAsyncClient.response = httpx.Response(
        200,
        content=b"x" * (engine._TARGET_RESPONSE_MAX_BYTES + 1),
        request=httpx.Request("POST", "https://example.com"),
    )
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", None, "m", None, None
    )

    assert result == (
        "[INVALID_RESPONSE: endpoint response exceeds "
        f"{engine._TARGET_RESPONSE_MAX_BYTES} bytes]"
    )


async def test_custom_endpoint_rejects_compressed_response_before_decompression(monkeypatch):
    class CompressedResponse:
        status_code = 200
        headers = {"content-encoding": "gzip"}

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, chunk_size=None):
            raise AssertionError("compressed content must be rejected before iteration")

    FakeAsyncClient.error = None
    FakeAsyncClient.response = CompressedResponse()
    monkeypatch.setattr(engine.httpx, "AsyncClient", FakeAsyncClient)

    result = await engine.call_target(
        "p", "s", "https://example.com", None, "m", None, None
    )

    assert result == "[INVALID_RESPONSE: compressed endpoint responses are not allowed]"


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
    captured = {}
    class Completions:
        async def create(self, **kwargs):
            captured.update(kwargs)
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
    assert [message["role"] for message in captured["messages"]] == ["system", "user"]
    assert "untrusted data" in captured["messages"][0]["content"]
    evidence = json.loads(captured["messages"][1]["content"].split("\n", 1)[1])
    assert evidence["actual_model_response"] == "response"


async def test_anthropic_judge_keeps_instructions_out_of_evidence_message():
    captured = {}
    content = '{"exploited": false, "confidence": 0.9, "reasoning": "refused"}'

    class Messages:
        async def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(content=[SimpleNamespace(text=content)])

    client = SimpleNamespace(messages=Messages())
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="A", description="d",
        payload="ordinary test", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    result = await engine.evaluate_with_judge(
        attack, "system prompt", "ordinary response", client,
        judge_provider="anthropic",
    )

    assert result == (False, 0.9, "refused")
    assert "untrusted data" in captured["system"]
    assert captured["messages"][0]["role"] == "user"
    evidence = json.loads(captured["messages"][0]["content"].split("\n", 1)[1])
    assert evidence["actual_model_response"] == "ordinary response"


async def test_judge_rejects_string_boolean_and_uses_heuristic():
    content = '{"exploited": "false", "confidence": 0.9, "reasoning": "refused"}'

    class Completions:
        async def create(self, **kwargs):
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="A", description="d",
        payload="p", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    exploited, confidence, reasoning = await engine.evaluate_with_judge(
        attack, "system prompt", "ordinary response", None, client, "openai"
    )

    assert exploited is False
    assert confidence == .55
    assert "Heuristic" in reasoning


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
    assert [message["role"] for message in captured["messages"]] == ["system", "user"]


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
    assert "not a security certification" in summary


async def test_scan_redacts_target_key_before_judging_and_results(monkeypatch):
    secret = "reflected-target-key"
    attack = AttackPrompt(
        id="a", category="prompt_injection", name="Injection A", description="d",
        payload="payload", severity=RiskLevel.HIGH, owasp_ref="LLM01",
        expected_safe_behavior="refuse",
    )

    class ReflectingProvider:
        async def call_target(self, payload, system_prompt):
            return f"endpoint diagnostic: {secret}"

        async def judge(self, received_attack, system_prompt, response):
            assert secret not in response
            return False, 0.9, f"reasoning should not contain {secret}"

    monkeypatch.setattr(engine, "load_attack_library", lambda categories: [attack])
    monkeypatch.setattr(engine.asyncio, "sleep", lambda _delay: _async_noop())

    results, *_ = await engine.run_scan(
        scan_id="scan", system_prompt="system", feature_description="feature",
        categories=["prompt_injection"], endpoint_url="https://example.com",
        api_key=secret, model_name="model", anthropic_client=None,
        openai_client=None, provider=ReflectingProvider(),
    )

    assert secret not in results[0].model_response
    assert secret not in results[0].judge_reasoning


def test_checked_in_attack_corpus_has_expected_counts_ids_and_owasp_refs():
    expected_counts = {
        AttackCategory.PROMPT_INJECTION: 15,
        AttackCategory.DATA_EXTRACTION: 10,
        AttackCategory.JAILBREAK: 10,
        AttackCategory.ROLE_CONFUSION: 7,
        AttackCategory.MULTI_TURN: 8,
    }
    attacks = engine.load_attack_library(list(AttackCategory))
    counts = Counter(attack.category for attack in attacks)

    assert counts == Counter({category.value: count for category, count in expected_counts.items()})
    assert len(attacks) == 50
    assert len({attack.id for attack in attacks}) == 50
    sensitive_disclosure_ids = {"de_008", "de_010"}
    hidden_context_ids = {
        "de_001", "de_002", "de_003", "de_004", "de_005",
        "de_006", "de_007", "de_009", "mt_007", "mt_008",
    }
    prompt_injection_ids = {
        *(f"pi_{index:03}" for index in range(1, 16)),
        *(f"jb_{index:03}" for index in range(1, 11)),
        *(f"rc_{index:03}" for index in range(1, 8)),
        *(f"mt_{index:03}" for index in range(1, 7)),
    }
    expected_refs = {
        **{attack_id: "LLM01:2026" for attack_id in prompt_injection_ids},
        **{attack_id: "LLM02:2026" for attack_id in sensitive_disclosure_ids},
        **{attack_id: "LLM08:2026" for attack_id in hidden_context_ids},
    }
    assert {attack.id for attack in attacks} == set(expected_refs)
    assert {attack.id: attack.owasp_ref for attack in attacks} == expected_refs


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
