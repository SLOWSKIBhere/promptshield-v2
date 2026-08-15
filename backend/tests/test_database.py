from datetime import datetime, timezone

import database
from models import ScanResult, ScanStatus


def test_persistence_across_connections(db_path, scan_factory):
    scan_factory("persist", current_attack_index=3, current_attack_name="Third")
    loaded = database.get_scan("persist")
    assert loaded.scan_id == "persist"
    assert loaded.current_attack_index == 3
    assert loaded.current_attack_name == "Third"


def test_orphaned_running_scan_recovery(db_path, scan_factory):
    scan_factory("running", ScanStatus.RUNNING)
    scan_factory("done", ScanStatus.COMPLETED, completed_at=datetime.now(timezone.utc))
    assert database.mark_orphaned_scans_interrupted() == 1
    recovered = database.get_scan("running")
    assert recovered.status == ScanStatus.INTERRUPTED
    assert recovered.completed_at is not None
    assert "restart" in recovered.failure_reason
    assert database.get_scan("done").status == ScanStatus.COMPLETED
