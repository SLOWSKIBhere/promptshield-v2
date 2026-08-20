from __future__ import annotations

import os
from pathlib import Path

import pytest

from llm_security.redaction import redact_evidence
from llm_security.static_scanner import ScanLimits, scan_tree


def test_static_rules_have_exact_locations_and_stable_order(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "system_prompt = 'API_KEY=sk-supersecret123456'\n"
        "model = AutoModel.from_pretrained('reviewed/model')\n"
        "answer = client.responses.create(model='test', input='hello')\n"
        "safe = client.responses.create(model='test', input='hello', max_output_tokens=20)\n"
        "command = safe.output_text\n"
        "os.system(command)\n",
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)

    assert [(item.rule, item.file, item.line) for item in result.findings] == [
        ("PS-LLM02-001", "app.py", 1),
        ("PS-LLM04-001", "app.py", 2),
        ("PS-LLM06-001", "app.py", 3),
        ("PS-LLM10-001", "app.py", 6),
    ]
    serialized = result.model_dump_json()
    assert "sk-supersecret123456" not in serialized
    assert result.files_scanned == 1


def test_safe_pinning_limits_and_non_shell_subprocess_do_not_trigger(tmp_path):
    (tmp_path / "safe.py").write_text(
        "model = AutoModel.from_pretrained('reviewed/model', revision='0123456789abcdef0123456789abcdef01234567')\n"
        "answer = client.chat.completions.create(model='test', messages=[], max_tokens=20)\n"
        "subprocess.run(['echo', answer.choices[0].message.content], shell=False)\n",
        encoding="utf-8",
    )

    assert scan_tree(tmp_path).findings == []


def test_credential_in_system_message_dictionary_is_detected_without_disclosure(tmp_path):
    secret = "sk-dictionarysecret123"
    (tmp_path / "messages.py").write_text(
        f"messages = [{{'role': 'system', 'content': 'Bearer {secret}'}}]\n",
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)

    assert [(item.rule, item.line) for item in result.findings] == [("PS-LLM02-001", 1)]
    assert secret not in result.model_dump_json()


def test_direct_eval_exec_and_shell_enabled_subprocess_are_detected(tmp_path):
    (tmp_path / "sinks.py").write_text(
        "a = client.messages.create(model='x', messages=[], max_tokens=5)\n"
        "eval(a.text)\n"
        "b = client.generate_content('x', max_output_tokens=5)\n"
        "exec(b.text)\n"
        "c = client.responses.create(model='x', input='x', max_output_tokens=5)\n"
        "subprocess.run(args=c.output_text, shell=True)\n",
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)
    assert [(item.rule, item.line) for item in result.findings] == [
        ("PS-LLM10-001", 2),
        ("PS-LLM10-001", 4),
        ("PS-LLM10-001", 6),
    ]


def test_diagnostics_cover_syntax_size_and_aggregate_limits(tmp_path):
    (tmp_path / "a_bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "b_large.py").write_text("x = '" + ("x" * 80) + "'", encoding="utf-8")
    (tmp_path / "c_more.py").write_text("x = 1\n", encoding="utf-8")

    result = scan_tree(
        tmp_path,
        limits=ScanLimits(max_files=10, max_file_bytes=50, max_total_bytes=20),
    )

    assert [(item.code, item.file) for item in result.diagnostics] == [
        ("total_bytes_exceeded", None),
        ("syntax_error", "a_bad.py"),
        ("file_too_large", "b_large.py"),
    ]


def test_file_limit_is_a_diagnostic(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 2\n", encoding="utf-8")

    result = scan_tree(tmp_path, limits=ScanLimits(max_files=1))

    assert result.files_scanned == 1
    assert [item.code for item in result.diagnostics] == ["file_limit_reached"]


def test_ignored_directories_env_files_and_non_python_files_are_not_scanned(tmp_path):
    for directory in (".git", ".venv", ".env-cache", "node_modules", "reports", "__pycache__"):
        path = tmp_path / directory
        path.mkdir()
        (path / "unsafe.py").write_text("eval(client.responses.create())", encoding="utf-8")
    (tmp_path / ".env.py").write_text("eval(client.responses.create())", encoding="utf-8")
    (tmp_path / "payload.bin").write_bytes(b"\x00\xff")
    (tmp_path / "valid.py").write_text("x = 1\n", encoding="utf-8")

    result = scan_tree(tmp_path)

    assert result.files_scanned == 1
    assert result.findings == []


def test_non_utf8_python_file_becomes_read_diagnostic(tmp_path):
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00")

    result = scan_tree(tmp_path)

    assert [(item.code, item.file) for item in result.diagnostics] == [("read_error", "binary.py")]


def test_symlinks_are_never_followed(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("eval(client.responses.create())", encoding="utf-8")
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not available to this test process")

    result = scan_tree(tmp_path)

    assert result.findings == []
    assert [(item.code, item.file) for item in result.diagnostics] == [
        ("skipped_symlink", "escape.py")
    ]


def test_redaction_masks_exact_secrets_credentials_controls_and_bounds():
    secret = "ordinary-value-123"
    value = f"before\x00 API_KEY=sk-secretvalue123 {secret} " + ("x" * 600)

    redacted = redact_evidence(value, exact_secrets=[secret])

    assert secret not in redacted
    assert "sk-secretvalue123" not in redacted
    assert "\x00" not in redacted
    assert len(redacted) <= 500
