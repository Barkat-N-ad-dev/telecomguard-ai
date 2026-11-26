"""Shared pytest fixtures providing isolated temporary SQLite & ChromaDB environments."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from telecomguard.backend.database import configure_database, init_db


@pytest.fixture(scope="session", autouse=True)
def isolated_test_env(tmp_path_factory):
    """Ensure tests run in a clean isolated SQLite database without touching dev state or needing API keys."""
    os.environ.pop("GEMINI_API_KEY", None)
    test_dir: Path = tmp_path_factory.mktemp("telecomguard_test")
    db_path = test_dir / "test_telecomguard.db"
    configure_database(f"sqlite:///{db_path.as_posix()}")
    init_db(seed=True)
    yield test_dir
