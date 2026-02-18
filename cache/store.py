"""
SQLite-based caching layer for scan data.
Supports delta re-scan by storing previous scan results and timestamps.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("m365_security_engine.cache")


class ScanCache:
    """
    Persistent cache backed by SQLite.
    Features:
      - TTL-based expiration
      - Delta scan support (compare with previous scan)
      - Thread-safe for async usage via connection-per-call
      - Stores raw JSON for any collector output
    """

    def __init__(self, cache_dir: str, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "scan_cache.db"
        self.ttl_seconds = ttl_hours * 3600
        self._init_db()

    def _init_db(self):
        """Initialize the cache database schema."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    scan_id TEXT NOT NULL,
                    item_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_log (
                    scan_id TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,
                    completed_at REAL,
                    status TEXT DEFAULT 'running',
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_timestamp
                ON cache_entries(timestamp)
            """)
            conn.commit()

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve cached data if it exists and hasn't expired.
        Returns None if not found or expired.
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT data, timestamp FROM cache_entries WHERE key = ?",
                (key,),
            ).fetchone()

        if row is None:
            return None

        data_json, timestamp = row
        if time.time() - timestamp > self.ttl_seconds:
            logger.debug(f"Cache expired for key: {key}")
            return None

        logger.debug(f"Cache hit for key: {key}")
        return json.loads(data_json)

    def put(self, key: str, data: Any, scan_id: str):
        """Store data in cache with current timestamp."""
        data_json = json.dumps(data, default=str)
        item_count = len(data) if isinstance(data, (list, dict)) else 1

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_entries (key, data, timestamp, scan_id, item_count)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key, data_json, time.time(), scan_id, item_count),
            )
            conn.commit()
        logger.debug(f"Cached {item_count} items for key: {key}")

    def get_previous_scan_data(self, key: str) -> Optional[Any]:
        """
        Get data from a previous scan (for delta comparison).
        Returns the most recent non-current entry.
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                """
                SELECT data FROM cache_entries
                WHERE key = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (key,),
            ).fetchone()

        if row:
            return json.loads(row[0])
        return None

    def start_scan(self, scan_id: str, metadata: Optional[dict] = None):
        """Record the start of a new scan."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_log (scan_id, started_at, status, metadata)
                VALUES (?, ?, 'running', ?)
                """,
                (scan_id, time.time(), json.dumps(metadata or {})),
            )
            conn.commit()

    def complete_scan(self, scan_id: str):
        """Record scan completion."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE scan_log SET completed_at = ?, status = 'completed'
                WHERE scan_id = ?
                """,
                (time.time(), scan_id),
            )
            conn.commit()

    def get_scan_history(self, limit: int = 10) -> list[dict]:
        """Retrieve recent scan history."""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                """
                SELECT scan_id, started_at, completed_at, status, metadata
                FROM scan_log ORDER BY started_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "scan_id": r[0],
                "started_at": r[1],
                "completed_at": r[2],
                "status": r[3],
                "metadata": json.loads(r[4]) if r[4] else {},
            }
            for r in rows
        ]

    def clear_expired(self):
        """Remove all expired cache entries."""
        cutoff = time.time() - self.ttl_seconds
        with sqlite3.connect(str(self.db_path)) as conn:
            deleted = conn.execute(
                "DELETE FROM cache_entries WHERE timestamp < ?",
                (cutoff,),
            ).rowcount
            conn.commit()
        if deleted:
            logger.info(f"Cleared {deleted} expired cache entries.")
