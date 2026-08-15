from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import database
import main
from models import ScanResult, ScanStatus


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()
    return path


@pytest.fixture
def client(db_path, monkeypatch):
    async def no_op_background(scan_id, target):
        return None

    monkeypatch.setattr(main, "_run_scan_background", no_op_background)
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def scan_factory(db_path):
    def make(scan_id="scan-1", status=ScanStatus.RUNNING, **overrides):
        values = {
            "scan_id": scan_id,
            "scan_name": f"Scan {scan_id}",
            "feature_description": "A sufficiently long feature description",
            "system_prompt_preview": "You are a helpful test assistant.",
            "started_at": datetime.now(timezone.utc),
            "status": status,
        }
        values.update(overrides)
        scan = ScanResult(**values)
        database.save_scan(scan)
        return scan
    return make
