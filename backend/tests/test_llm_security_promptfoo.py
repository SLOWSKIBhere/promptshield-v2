from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from llm_security import promptfoo_runner
from llm_security.normalizers import normalize_promptfoo


def _metadata():
    return {
        "risk_id": "LLM01:2026",
        "title": "Injection marker returned",
        "severity": "high",
        "confidence": 0.8,
        "rule": "PS-PF-LLM01-001",
        "description": "A deterministic assertion failed.",
        "remediation": "Keep instructions separate from untrusted input.",
    }


def _payload(*, success=True, output="safe", reason="assertion passed"):
    return {
        "version": 3,
        "results": [{
            "success": success,
            "response": {"output": output},
            "gradingResult": {"pass": success, "reason": reason},
            "testCase": {"metadata": _metadata()},
        }],
    }


class _FinishedProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.pid = 4321

    def poll(self):
        return self.returncode


def test_runner_rejects_any_non_fixture_target(monkeypatch):
    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: pytest.fail("must not launch"))

    result = promptfoo_runner.run_promptfoo(target="https://example.test")

    assert result.errors[0].code == "unauthorized_target"


def test_missing_executable_is_structured(monkeypatch):
    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: None)

    result = promptfoo_runner.run_promptfoo()

    assert result.findings == []
    assert result.errors[0].code == "not_installed"


def test_fixed_argv_and_minimal_environment(monkeypatch):
    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        output = Path(argv[argv.index("-o") + 1])
        output.write_text(json.dumps(_payload()), encoding="utf-8")
        return _FinishedProcess()

    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "C:/tools/promptfoo.cmd")
    monkeypatch.setattr(promptfoo_runner.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-pass")

    result = promptfoo_runner.run_promptfoo()

    assert result.errors == []
    assert captured["argv"][0:3] == ["C:/tools/promptfoo.cmd", "redteam", "eval"]
    assert captured["argv"][-2:] == ["-j", "1"]
    assert "--no-share" in captured["argv"]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is promptfoo_runner.subprocess.DEVNULL
    environment = captured["kwargs"]["env"]
    assert "OPENAI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert environment["PROMPTFOO_DISABLE_TELEMETRY"] == "1"


def test_reviewed_config_is_finite_deterministic_and_loopback_only():
    config = yaml.safe_load(promptfoo_runner.CONFIG_PATH.read_text(encoding="utf-8"))

    assert config["sharing"] is False
    assert len(config["providers"]) == 1
    assert config["providers"][0]["config"]["url"] == promptfoo_runner.LOCAL_FIXTURE_URL
    assert "transformResponse" not in config["providers"][0]["config"]
    assert 0 < len(config["tests"]) <= 10
    assert all(
        assertion["type"] == "not-contains"
        for case in config["tests"]
        for assertion in case["assert"]
    )
    assert "redteam" not in config


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("", "empty_result"),
        ("not json", "invalid_json"),
        (json.dumps({"version": 2, "results": []}), "unsupported_schema"),
        (json.dumps({"version": 3, "results": []}), "no_tests_executed"),
    ],
)
def test_result_failures_are_structured(monkeypatch, content, code):
    def launch(argv, **_kwargs):
        Path(argv[argv.index("-o") + 1]).write_text(content, encoding="utf-8")
        return _FinishedProcess()

    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "promptfoo")
    monkeypatch.setattr(promptfoo_runner, "_launch", launch)

    result = promptfoo_runner.run_promptfoo()

    assert result.findings == []
    assert result.errors[0].code == code


def test_nonzero_exit_does_not_parse_findings(monkeypatch):
    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "promptfoo")
    monkeypatch.setattr(promptfoo_runner, "_launch", lambda *_args, **_kwargs: _FinishedProcess(7))

    result = promptfoo_runner.run_promptfoo()

    assert result.findings == []
    assert result.errors[0].code == "nonzero_exit"
    assert result.errors[0].exit_code == 7


def test_missing_result_after_success_is_structured(monkeypatch):
    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "promptfoo")
    monkeypatch.setattr(promptfoo_runner, "_launch", lambda *_args, **_kwargs: _FinishedProcess())

    result = promptfoo_runner.run_promptfoo()

    assert result.findings == []
    assert result.errors[0].code == "empty_result"


def test_timeout_stops_process_group(monkeypatch):
    class RunningProcess(_FinishedProcess):
        def poll(self):
            return None

    stopped = []
    times = iter([0.0, 1.0])
    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "promptfoo")
    monkeypatch.setattr(promptfoo_runner, "_launch", lambda *_args, **_kwargs: RunningProcess())
    monkeypatch.setattr(promptfoo_runner, "_stop_process", lambda process: stopped.append(process.pid))
    monkeypatch.setattr(promptfoo_runner.time, "monotonic", lambda: next(times))

    result = promptfoo_runner.run_promptfoo(timeout_seconds=0.5)

    assert result.errors[0].code == "timeout"
    assert stopped == [4321]


def test_oversized_output_stops_process_group(monkeypatch):
    class RunningProcess(_FinishedProcess):
        def poll(self):
            return None

    stopped = []

    def launch(argv, **_kwargs):
        Path(argv[argv.index("-o") + 1]).write_bytes(b"x" * 20)
        return RunningProcess()

    monkeypatch.setattr(promptfoo_runner.shutil, "which", lambda _: "promptfoo")
    monkeypatch.setattr(promptfoo_runner, "_launch", launch)
    monkeypatch.setattr(promptfoo_runner, "_stop_process", lambda process: stopped.append(process.pid))

    result = promptfoo_runner.run_promptfoo(max_result_bytes=10)

    assert result.errors[0].code == "output_too_large"
    assert stopped == [4321]


def test_valid_failure_becomes_redacted_finding():
    payload = _payload(
        success=False,
        output="API_KEY=sk-secretvalue123\x00",
        reason="prohibited marker returned",
    )

    result = normalize_promptfoo(payload)

    assert result.errors == []
    assert result.tests_executed == 1
    assert len(result.findings) == 1
    assert "sk-secretvalue123" not in result.findings[0].redacted_evidence
    assert "\x00" not in result.findings[0].redacted_evidence


def test_transport_or_grader_failure_is_not_a_vulnerability():
    payload = _payload(success=False)
    payload["results"][0]["gradingResult"]["graderError"] = "provider failed"

    result = normalize_promptfoo(payload)

    assert result.findings == []
    assert result.errors[0].code == "evaluation_error"


def test_missing_assertion_outcome_is_not_a_vulnerability():
    payload = _payload(success=True)
    del payload["results"][0]["success"]
    del payload["results"][0]["gradingResult"]["pass"]

    result = normalize_promptfoo(payload)

    assert result.findings == []
    assert result.errors[0].code == "evaluation_error"
