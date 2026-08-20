"""Bounded deterministic Python AST checks for selected OWASP LLM risks."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from models import RiskLevel

from .models import NormalizedFinding, ScanDiagnostic, StaticScanResult
from .redaction import REDACTED, contains_credential, redact_evidence


@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 2_000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 20_000_000

    def __post_init__(self) -> None:
        if self.max_files <= 0 or self.max_file_bytes <= 0 or self.max_total_bytes <= 0:
            raise ValueError("scan limits must be positive")


_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "site-packages",
    ".eggs",
    "vendor",
    "third_party",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".cache",
    "dist",
    "build",
    "reports",
    "htmlcov",
    "coverage",
}
_OUTPUT_LIMITS = {"max_tokens", "max_output_tokens", "max_new_tokens", "max_completion_tokens"}
_GENERATION_SUFFIXES = (
    ".chat.completions.create",
    ".messages.create",
    ".responses.create",
    ".generate_content",
    ".generate",
)
_MODEL_LOAD_SUFFIXES = (".from_pretrained", "snapshot_download")
_SHELL_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
_SYSTEM_INSTRUCTION_NAMES = {"system", "system_prompt", "system_message", "system_instructions", "instructions"}
_IMMUTABLE_REVISION = re.compile(r"^(?:[0-9a-fA-F]{7,64}|sha256:[0-9a-fA-F]{64})$")


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_generation_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _dotted_name(node.func)
    return any(name.endswith(suffix) for suffix in _GENERATION_SUFFIXES)


def _contains_generation_call(node: ast.AST) -> bool:
    return any(_is_generation_call(item) for item in ast.walk(node))


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in node.elts:
            names.update(_target_names(item))
        return names
    return set()


def _expr_is_tainted(node: ast.AST, tainted: set[str]) -> bool:
    if _contains_generation_call(node):
        return True
    return any(isinstance(item, ast.Name) and item.id in tainted for item in ast.walk(node))


def _iter_scope_nodes(scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef) -> Iterable[ast.AST]:
    stack = list(reversed(scope.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        children = list(ast.iter_child_nodes(node))
        stack.extend(reversed(children))


class _RuleCollector:
    def __init__(self, *, relative_file: str, source: str) -> None:
        self.relative_file = relative_file
        self.source = source
        self.findings: list[NormalizedFinding] = []
        self._seen: set[tuple[str, int]] = set()

    def add(
        self,
        *,
        node: ast.AST,
        rule: str,
        risk_id: str,
        title: str,
        severity: RiskLevel,
        confidence: float,
        description: str,
        remediation: str,
        evidence: str,
    ) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(NormalizedFinding(
            source="static",
            risk_id=risk_id,
            title=title,
            severity=severity,
            confidence=confidence,
            file=self.relative_file,
            line=line,
            rule=rule,
            description=description,
            remediation=remediation,
            redacted_evidence=redact_evidence(evidence),
        ))

    def inspect_tree(self, tree: ast.Module) -> None:
        self._inspect_secret_literals(tree)
        self._inspect_model_pinning(tree)
        self._inspect_generation_limits(tree)
        self._inspect_output_sinks(tree)

    def _inspect_secret_literals(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            name = ""
            value: ast.AST | None = None
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = set().union(*(_target_names(target) for target in targets))
                matched = sorted(item for item in names if item.lower() in _SYSTEM_INSTRUCTION_NAMES)
                if matched:
                    name = matched[0]
                    value = node.value
            elif isinstance(node, ast.keyword) and node.arg and node.arg.lower() in _SYSTEM_INSTRUCTION_NAMES:
                name = node.arg
                value = node.value
            elif isinstance(node, ast.Dict):
                entries = {
                    key.value.lower(): item
                    for key, item in zip(node.keys, node.values)
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
                role = entries.get("role")
                if (
                    isinstance(role, ast.Constant)
                    and isinstance(role.value, str)
                    and role.value.lower() in {"system", "developer"}
                ):
                    name = f"{role.value.lower()} message"
                    value = entries.get("content") or entries.get("text")
            if value is None:
                continue
            literals = [item.value for item in ast.walk(value) if isinstance(item, ast.Constant) and isinstance(item.value, str)]
            if any(contains_credential(literal) for literal in literals):
                self.add(
                    node=node,
                    rule="PS-LLM02-001",
                    risk_id="LLM02:2026",
                    title="Credential-like literal in system instructions",
                    severity=RiskLevel.HIGH,
                    confidence=0.95,
                    description="System instructions contain a credential-like literal that may be disclosed through model context.",
                    remediation="Remove credentials from prompts and retrieve secrets only in trusted application code when required.",
                    evidence=f"{name} contains credential-like literal: {REDACTED}",
                )

    def _inspect_model_pinning(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted_name(node.func)
            if not any(name.endswith(suffix) for suffix in _MODEL_LOAD_SUFFIXES):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                continue
            model_id = node.args[0].value
            if model_id.startswith((".", "/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", model_id):
                continue
            revision = next((keyword.value for keyword in node.keywords if keyword.arg in {"revision", "commit_hash", "digest"}), None)
            pinned = isinstance(revision, ast.Constant) and isinstance(revision.value, str) and bool(_IMMUTABLE_REVISION.fullmatch(revision.value))
            if not pinned:
                self.add(
                    node=node,
                    rule="PS-LLM04-001",
                    risk_id="LLM04:2026",
                    title="Remote model artifact is not immutably pinned",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.80,
                    description="A remote model or artifact is loaded without an immutable commit or digest.",
                    remediation="Pin remote model artifacts to a reviewed immutable commit hash or cryptographic digest.",
                    evidence=ast.get_source_segment(self.source, node) or name,
                )

    def _inspect_generation_limits(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not _is_generation_call(node):
                continue
            keyword_names = {keyword.arg for keyword in node.keywords if keyword.arg}
            if keyword_names.isdisjoint(_OUTPUT_LIMITS):
                self.add(
                    node=node,
                    rule="PS-LLM06-001",
                    risk_id="LLM06:2026",
                    title="Generation call has no explicit output-token bound",
                    severity=RiskLevel.MEDIUM,
                    confidence=0.75,
                    description="A recognized model generation call does not set an explicit output-token limit.",
                    remediation="Set a bounded provider-supported output-token limit and enforce request/session budgets outside the model.",
                    evidence=ast.get_source_segment(self.source, node) or _dotted_name(node.func),
                )

    def _inspect_output_sinks(self, tree: ast.Module) -> None:
        scopes: list[ast.Module | ast.FunctionDef | ast.AsyncFunctionDef] = [tree]
        scopes.extend(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
        for scope in scopes:
            nodes = list(_iter_scope_nodes(scope))
            tainted: set[str] = set()
            changed = True
            while changed:
                changed = False
                for node in nodes:
                    targets: set[str] = set()
                    value: ast.AST | None = None
                    if isinstance(node, ast.Assign):
                        targets = set().union(*(_target_names(target) for target in node.targets))
                        value = node.value
                    elif isinstance(node, ast.AnnAssign):
                        targets = _target_names(node.target)
                        value = node.value
                    if value is not None and targets and _expr_is_tainted(value, tainted):
                        new_names = targets - tainted
                        if new_names:
                            tainted.update(new_names)
                            changed = True

            for node in nodes:
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted_name(node.func)
                dangerous = name in {"eval", "exec", "os.system"}
                if name in _SHELL_CALLS:
                    dangerous = any(
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in node.keywords
                    )
                sink_values = list(node.args)
                sink_values.extend(
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg in {"args", "command", "source", "object"}
                )
                if dangerous and any(_expr_is_tainted(argument, tainted) for argument in sink_values):
                    self.add(
                        node=node,
                        rule="PS-LLM10-001",
                        risk_id="LLM10:2026",
                        title="Model output reaches a code or shell execution sink",
                        severity=RiskLevel.CRITICAL,
                        confidence=0.95,
                        description="Model-controlled output is passed directly to a dynamic code or shell execution sink.",
                        remediation="Never execute model output directly; use a strict allowlisted operation schema and trusted argument validation.",
                        evidence=ast.get_source_segment(self.source, node) or name,
                    )


def _relative(candidate: Path, root: Path) -> str:
    return candidate.relative_to(root).as_posix()


def scan_tree(root: Path, *, limits: ScanLimits = ScanLimits()) -> StaticScanResult:
    """Scan bounded Python source beneath root without following symlinks."""
    requested_root = Path(root)
    try:
        resolved_root = requested_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return StaticScanResult(diagnostics=[ScanDiagnostic(
            code="invalid_root",
            message="Source root does not exist or cannot be resolved.",
        )])
    if not resolved_root.is_dir():
        return StaticScanResult(diagnostics=[ScanDiagnostic(
            code="invalid_root",
            message="Source root must be a directory.",
        )])

    findings: list[NormalizedFinding] = []
    diagnostics: list[ScanDiagnostic] = []
    files_scanned = 0
    files_considered = 0
    bytes_scanned = 0
    stop = False

    for directory, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        current = Path(directory)
        kept_dirs = []
        for dirname in sorted(dirnames):
            candidate = current / dirname
            if dirname in _EXCLUDED_DIRS or dirname.lower().startswith(".env"):
                continue
            if candidate.is_symlink():
                relative_directory = _relative(candidate, resolved_root)
                diagnostics.append(ScanDiagnostic(
                    code="skipped_symlink",
                    message="Symbolic-link directory was not scanned.",
                    file=relative_directory if len(relative_directory) <= 500 else None,
                ))
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            candidate = current / filename
            if candidate.suffix.lower() != ".py" or candidate.name.lower().startswith(".env"):
                continue
            if files_considered >= limits.max_files:
                diagnostics.append(ScanDiagnostic(
                    code="file_limit_reached",
                    message="Maximum source-file count reached; remaining files were skipped.",
                ))
                stop = True
                break
            files_considered += 1
            relative_file = _relative(candidate, resolved_root)
            if len(relative_file) > 500:
                diagnostics.append(ScanDiagnostic(
                    code="read_error",
                    message="Source path exceeded the normalized report path limit.",
                ))
                continue
            if candidate.is_symlink():
                diagnostics.append(ScanDiagnostic(
                    code="skipped_symlink",
                    message="Symbolic-link file was not scanned.",
                    file=relative_file,
                ))
                continue
            try:
                size = candidate.stat().st_size
            except OSError:
                diagnostics.append(ScanDiagnostic(
                    code="read_error",
                    message="Source file metadata could not be read.",
                    file=relative_file,
                ))
                continue
            if size > limits.max_file_bytes:
                diagnostics.append(ScanDiagnostic(
                    code="file_too_large",
                    message="Source file exceeded the per-file byte limit.",
                    file=relative_file,
                ))
                continue
            if bytes_scanned + size > limits.max_total_bytes:
                diagnostics.append(ScanDiagnostic(
                    code="total_bytes_exceeded",
                    message="Maximum aggregate source byte count reached; remaining files were skipped.",
                ))
                stop = True
                break
            try:
                source = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                diagnostics.append(ScanDiagnostic(
                    code="read_error",
                    message="Source file could not be read as UTF-8 text.",
                    file=relative_file,
                ))
                continue
            files_scanned += 1
            bytes_scanned += size
            try:
                tree = ast.parse(source, filename=relative_file)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
                diagnostics.append(ScanDiagnostic(
                    code="syntax_error",
                    message="Python source could not be parsed.",
                    file=relative_file,
                    line=max(1, error.lineno or 1) if isinstance(error, SyntaxError) else 1,
                ))
                continue
            collector = _RuleCollector(relative_file=relative_file, source=source)
            collector.inspect_tree(tree)
            findings.extend(collector.findings)
        if stop:
            break

    findings.sort(key=lambda finding: (finding.file or "", finding.line or 0, finding.rule))
    diagnostics.sort(key=lambda item: (item.file or "", item.line or 0, item.code))
    return StaticScanResult(
        findings=findings,
        diagnostics=diagnostics,
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
    )
