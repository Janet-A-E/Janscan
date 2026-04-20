"""SQLite database connection and initialization."""

import sqlite3
from pathlib import Path

_DB_PATH = None


def get_db_path() -> Path:
    global _DB_PATH
    if _DB_PATH is None:
        from janscan.config.loader import DATA_DIR
        _DB_PATH = DATA_DIR / "scans.db"
    return _DB_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    schema_path = Path(__file__).parent / "schema.sql"
    conn = get_connection()
    try:
        with open(schema_path) as f:
            conn.executescript(f.read())
        conn.commit()
    finally:
        conn.close()
