"""
database.py — SQLite persistence layer

Fixes applied:
  BUG-13: Replaced INSERT OR REPLACE with proper UPSERT (ON CONFLICT DO UPDATE)
  BUG-14: Added WAL journal mode + check_same_thread=False for concurrent access
  BUG-19: Replaced datetime.utcnow() with datetime.now(timezone.utc)
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, List
from models import ScanResult, ScanSummary
from config import settings

DB_PATH = settings.database_path


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)  # BUG-14 FIX
    conn.row_factory = sqlite3.Row
    # BUG-14 FIX: WAL mode allows concurrent reads during writes
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")  # safe + faster than FULL
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id             TEXT PRIMARY KEY,
                scan_name           TEXT NOT NULL,
                feature_description TEXT,
                system_prompt_preview TEXT,
                started_at          TEXT NOT NULL,
                completed_at        TEXT,
                status              TEXT NOT NULL DEFAULT 'running',
                total_attacks       INTEGER DEFAULT 0,
                exploited_count     INTEGER DEFAULT 0,
                overall_score       REAL DEFAULT 100.0,
                letter_grade        TEXT DEFAULT 'A+',
                findings_json       TEXT DEFAULT '[]',
                summary             TEXT,
                current_attack_index INTEGER DEFAULT 0,
                current_attack_name TEXT,
                failure_reason      TEXT
            )
        """)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        migrations = {
            "current_attack_index": "INTEGER DEFAULT 0",
            "current_attack_name": "TEXT",
            "failure_reason": "TEXT",
        }
        for column, definition in migrations.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
        # Index for list_scans sort performance
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_started_at
            ON scans (started_at DESC)
        """)
        conn.commit()


def save_scan(scan: ScanResult) -> None:
    findings_json = json.dumps([f.model_dump() for f in scan.findings])
    
    with get_connection() as conn:
        # BUG-13 FIX: True upsert — no delete+reinsert, preserves rowid
        conn.execute("""
            INSERT INTO scans (
                scan_id, scan_name, feature_description, system_prompt_preview,
                started_at, completed_at, status, total_attacks, exploited_count,
                overall_score, letter_grade, findings_json, summary,
                current_attack_index, current_attack_name, failure_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                scan_name           = excluded.scan_name,
                feature_description = excluded.feature_description,
                completed_at        = excluded.completed_at,
                status              = excluded.status,
                total_attacks       = excluded.total_attacks,
                exploited_count     = excluded.exploited_count,
                overall_score       = excluded.overall_score,
                letter_grade        = excluded.letter_grade,
                findings_json       = excluded.findings_json,
                summary             = excluded.summary,
                current_attack_index = excluded.current_attack_index,
                current_attack_name = excluded.current_attack_name,
                failure_reason      = excluded.failure_reason
        """, (
            scan.scan_id,
            scan.scan_name,
            scan.feature_description,
            scan.system_prompt_preview,
            scan.started_at.isoformat(),
            scan.completed_at.isoformat() if scan.completed_at else None,
            scan.status,
            scan.total_attacks,
            scan.exploited_count,
            scan.overall_score,
            scan.letter_grade,
            findings_json,
            scan.summary,
            scan.current_attack_index,
            scan.current_attack_name,
            scan.failure_reason,
        ))
        conn.commit()


def get_scan(scan_id: str) -> Optional[ScanResult]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        return _row_to_scan(row)


def list_scans(limit: int = 50) -> List[ScanSummary]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_summary(r) for r in rows]


def delete_scan(scan_id: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def mark_orphaned_scans_interrupted() -> int:
    """Mark background scans lost during a process restart."""
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.execute(
            """UPDATE scans
               SET status = 'interrupted', completed_at = ?,
                   failure_reason = 'Scan interrupted by backend restart',
                   current_attack_name = 'Interrupted'
               WHERE status = 'running'""",
            (now,),
        )
        conn.commit()
        return cursor.rowcount


# ─── Private helpers ────────────────────────────────────────────────────────

def _row_to_scan(row: sqlite3.Row) -> ScanResult:
    from models import AttackResult
    findings_raw = json.loads(row["findings_json"] or "[]")
    findings = [AttackResult(**f) for f in findings_raw]
    return ScanResult(
        scan_id=row["scan_id"],
        scan_name=row["scan_name"],
        feature_description=row["feature_description"] or "",
        system_prompt_preview=row["system_prompt_preview"] or "",
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        status=row["status"],
        total_attacks=row["total_attacks"],
        exploited_count=row["exploited_count"],
        overall_score=row["overall_score"],
        letter_grade=row["letter_grade"],
        findings=findings,
        summary=row["summary"],
        current_attack_index=row["current_attack_index"] or 0,
        current_attack_name=row["current_attack_name"],
        failure_reason=row["failure_reason"],
    )


def _row_to_summary(row: sqlite3.Row) -> ScanSummary:
    findings = json.loads(row["findings_json"] or "[]")
    critical = sum(1 for f in findings if f.get("severity") == "critical" and f.get("is_exploited"))
    high     = sum(1 for f in findings if f.get("severity") == "high"     and f.get("is_exploited"))
    medium   = sum(1 for f in findings if f.get("severity") == "medium"   and f.get("is_exploited"))
    return ScanSummary(
        scan_id=row["scan_id"],
        scan_name=row["scan_name"],
        letter_grade=row["letter_grade"],
        overall_score=row["overall_score"],
        total_attacks=row["total_attacks"],
        exploited_count=row["exploited_count"],
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        status=row["status"],
    )
