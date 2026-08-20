"""Constrained local-only Promptfoo subprocess integration."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Literal

from .models import ToolError, ToolErrorCode, ToolRunResult
from .normalizers import normalize_promptfoo


LOCAL_TARGET = "local_fixture"
LOCAL_FIXTURE_URL = "http://127.0.0.1:9000/chat"
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_RESULT_BYTES = 1_000_000
CONFIG_PATH = Path(__file__).with_name("config") / "promptfoo.local.yaml"

_PASSTHROUGH_ENVIRONMENT = ("PATH", "PATHEXT", "SystemRoot", "WINDIR", "ComSpec")


def _error(code: ToolErrorCode, message: str, *, exit_code: int | None = None) -> ToolRunResult:
    return ToolRunResult(errors=[ToolError(code=code, message=message, exit_code=exit_code)])


def _minimal_environment(workdir: Path) -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in _PASSTHROUGH_ENVIRONMENT
        if name in os.environ
    }
    environment.update({
        "CI": "true",
        "DO_NOT_TRACK": "1",
        "NO_COLOR": "1",
        "TEMP": str(workdir / "tmp"),
        "TMP": str(workdir / "tmp"),
        "PROMPTFOO_CONFIG_DIR": str(workdir / "config"),
        "PROMPTFOO_CACHE_PATH": str(workdir / "cache"),
        "PROMPTFOO_LOG_DIR": str(workdir / "logs"),
        "PROMPTFOO_DISABLE_TELEMETRY": "1",
        "PROMPTFOO_DISABLE_UPDATE": "true",
        "PROMPTFOO_DISABLE_SHARING": "true",
        "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "true",
        "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true",
    })
    return environment


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            taskkill = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "taskkill.exe"
            subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                check=False,
                timeout=5,
            )
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass


def _launch(
    argv: list[str],
    *,
    workdir: Path,
    environment: dict[str, str],
) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {
        "cwd": workdir,
        "env": environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)  # type: ignore[arg-type]


def run_promptfoo(
    *,
    target: Literal["local_fixture"] | str = LOCAL_TARGET,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_result_bytes: int = MAX_RESULT_BYTES,
) -> ToolRunResult:
    """Run a fixed Promptfoo config against the loopback fixture only."""
    if target != LOCAL_TARGET:
        return _error("unauthorized_target", "Promptfoo target is not authorized.")
    if timeout_seconds <= 0 or max_result_bytes <= 0:
        raise ValueError("Promptfoo limits must be positive")
    executable = shutil.which("promptfoo")
    if executable is None:
        return _error("not_installed", "Promptfoo is not installed or not available on PATH.")

    with tempfile.TemporaryDirectory(prefix="promptshield-promptfoo-") as temporary:
        workdir = Path(temporary)
        for name in ("tmp", "config", "cache", "logs"):
            (workdir / name).mkdir()
        result_path = workdir / "results.json"
        argv = [
            executable,
            "redteam",
            "eval",
            "-c",
            str(CONFIG_PATH.resolve()),
            "-o",
            str(result_path),
            "--no-cache",
            "--no-share",
            "--no-write",
            "--no-progress-bar",
            "--no-table",
            "-j",
            "1",
        ]
        try:
            process = _launch(argv, workdir=workdir, environment=_minimal_environment(workdir))
        except OSError:
            return _error("not_installed", "Promptfoo could not be started.")

        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if time.monotonic() >= deadline:
                _stop_process(process)
                return _error("timeout", "Promptfoo exceeded the configured time limit.")
            try:
                if result_path.exists() and result_path.stat().st_size > max_result_bytes:
                    _stop_process(process)
                    return _error("output_too_large", "Promptfoo result exceeded the configured size limit.")
            except OSError:
                _stop_process(process)
                return _error("invalid_json", "Promptfoo result could not be inspected.")
            time.sleep(0.05)

        exit_code = process.returncode
        if exit_code != 0:
            return _error(
                "nonzero_exit",
                "Promptfoo exited unsuccessfully.",
                exit_code=exit_code,
            )
        try:
            size = result_path.stat().st_size
        except OSError:
            return _error("empty_result", "Promptfoo did not produce a result file.")
        if size == 0:
            return _error("empty_result", "Promptfoo produced an empty result file.")
        if size > max_result_bytes:
            return _error("output_too_large", "Promptfoo result exceeded the configured size limit.")
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return _error("invalid_json", "Promptfoo produced malformed JSON output.")
        if not isinstance(payload, dict):
            return _error("invalid_json", "Promptfoo output must be a JSON object.")
        return normalize_promptfoo(payload)
