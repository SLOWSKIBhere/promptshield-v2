"""Command-line entry point for local defensive LLM-security scans."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from models import ScanResult

from .models import NormalizedFinding, ScanDiagnostic
from .normalizers import normalize_promptshield_scan
from .promptfoo_runner import run_promptfoo
from .reporting import build_report, report_json
from .static_scanner import scan_tree


MAX_PROMPTSHIELD_JSON_BYTES = 5_000_000


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m llm_security")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="run selected local defensive checks")
    scan.add_argument("--source-root", required=True, type=Path)
    scan.add_argument("--promptshield-json", type=Path)
    scan.add_argument("--promptfoo-local", action="store_true")
    scan.add_argument("--output", type=Path)
    return parser


def _load_promptshield(path: Path) -> tuple[list[NormalizedFinding], ScanDiagnostic | None]:
    try:
        if path.stat().st_size > MAX_PROMPTSHIELD_JSON_BYTES:
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
        scan = ScanResult.model_validate(payload)
        return list(normalize_promptshield_scan(scan)), None
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
        return [], ScanDiagnostic(
            code="invalid_promptshield_json",
            message="PromptShield input was missing, oversized, malformed, or incompatible.",
        )


def _is_root_reports(path: Path) -> bool:
    reports = Path(__file__).resolve().parents[2] / "reports"
    try:
        path.resolve().relative_to(reports.resolve())
        return True
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    static_result = scan_tree(args.source_root)
    finding_groups: list[list[NormalizedFinding]] = [list(static_result.findings)]
    diagnostics = list(static_result.diagnostics)
    input_error = any(item.code == "invalid_root" for item in diagnostics)

    if args.promptshield_json:
        runtime_findings, diagnostic = _load_promptshield(args.promptshield_json)
        finding_groups.append(runtime_findings)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            input_error = True

    tool_errors = []
    if args.promptfoo_local:
        promptfoo_result = run_promptfoo()
        finding_groups.append(list(promptfoo_result.findings))
        tool_errors.extend(promptfoo_result.errors)

    report = build_report(
        finding_groups,
        tool_errors=tool_errors,
        diagnostics=diagnostics,
    )
    serialized = report_json(report)
    if args.output:
        if _is_root_reports(args.output):
            print("Refusing to write CLI output to the repository reports directory.", file=sys.stderr)
            return 2
        try:
            args.output.write_text(serialized, encoding="utf-8")
        except OSError:
            print("Could not write the requested report output.", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(serialized)
    return 2 if tool_errors or input_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
