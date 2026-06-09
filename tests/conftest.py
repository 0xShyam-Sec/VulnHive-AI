"""Shared pytest fixtures for VulnHive tests."""

import asyncio
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Yield a path to a fresh empty SQLite file."""
    db_path = tmp_path / "test.db"
    return db_path


@pytest.fixture
def in_memory_db():
    """In-memory SQLite connection (no file I/O)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    yield conn
    conn.close()


@pytest.fixture
def event_loop():
    """Re-create the event loop per test (pytest-asyncio default in 0.23+)."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
