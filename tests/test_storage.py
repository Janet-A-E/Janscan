"""Storage layer tests."""

import pytest
import tempfile
import os
from pathlib import Path


def setup_temp_db(tmp_path):
    """Patch the DB path to a temp location."""
    import janscan.storage.db as db_mod
    db_mod._DB_PATH = tmp_path / "test.db"
    from janscan.storage.db import init_db
    init_db()
    return db_mod._DB_PATH


def test_save_and_retrieve_scan(tmp_path):
    setup_temp_db(tmp_path)
    from janscan.storage.queries import save_scan, get_scan_by_id
    import uuid

    scan_data = {
        "scan_uuid": str(uuid.uuid4()),
        "hostname": "testhost",
        "started_at": "2024-01-01T00:00:00",
        "finished_at": "2024-01-01T00:01:00",
        "duration_seconds": 60.0,
        "overall_score": 75,
        "grade": "B",
        "total_critical": 0,
        "total_high": 2,
        "total_medium": 5,
        "total_low": 3,
        "total_info": 10,
        "total_pass": 30,
    }
    scan_id = save_scan(scan_data)
    assert scan_id > 0

    retrieved = get_scan_by_id(scan_id)
    assert retrieved is not None
    assert retrieved["hostname"] == "testhost"
    assert retrieved["overall_score"] == 75


def test_list_scans(tmp_path):
    setup_temp_db(tmp_path)
    from janscan.storage.queries import save_scan, list_scans
    import uuid

    for i in range(3):
        save_scan({
            "scan_uuid": str(uuid.uuid4()),
            "hostname": f"host{i}",
            "started_at": f"2024-01-0{i+1}T00:00:00",
            "overall_score": 80,
            "grade": "B",
            "total_critical": 0, "total_high": 0,
            "total_medium": 0, "total_low": 0,
            "total_info": 0, "total_pass": 0,
        })

    scans = list_scans(limit=10)
    assert len(scans) == 3
