from __future__ import annotations

import os
import pytest


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """
    Ensure every test executes against an isolated temporary SQLite database file.
    Prevents cross-test pollution while testing real SQLite disk persistence.
    """
    test_db = tmp_path / "test_secmon.db"
    monkeypatch.setenv("SECMON_DB_PATH", str(test_db))
    yield test_db
