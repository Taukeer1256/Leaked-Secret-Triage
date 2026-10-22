"""
SQLite persistence layer for SecretTriage (Stage 5).

Persists scan summaries and finding records (storing masked values only, adhering
to zero-leak local storage constraints).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from secrettriage.detectors.models import Finding

_DEFAULT_DB_PATH = Path("secrettriage.db")


class Database:
    """SQLite database manager for scan sessions and findings."""

    def __init__(self, db_path: str | Path = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            if self.db_path != Path(":memory:"):
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self.init_schema()
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Database:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def init_schema(self) -> None:
        """Create necessary tables if they do not exist."""
        conn = self.connect()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_target TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    real_count INTEGER NOT NULL,
                    placeholder_count INTEGER NOT NULL,
                    uncertain_count INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    file TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    secret_type TEXT NOT NULL,
                    matched_value_masked TEXT NOT NULL,
                    detector_name TEXT NOT NULL,
                    pattern_id TEXT NOT NULL,
                    label TEXT,
                    label_confidence REAL,
                    label_reasons TEXT,
                    severity TEXT,
                    severity_score REAL,
                    severity_reasoning TEXT,
                    context_before TEXT,
                    context_after TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")

    def save_scan(self, scan_target: str, findings: list["Finding"]) -> int:
        """
        Record a scan run and all its findings.

        Returns:
            The generated scan_id.
        """
        conn = self.connect()
        now = datetime.now(timezone.utc).isoformat()

        crit_count = sum(1 for f in findings if f.severity == "Critical")
        high_count = sum(1 for f in findings if f.severity == "High")
        med_count = sum(1 for f in findings if f.severity == "Medium")
        low_count = sum(1 for f in findings if f.severity == "Low")

        real_count = sum(1 for f in findings if f.label == "LIKELY_REAL")
        ph_count = sum(1 for f in findings if f.label == "LIKELY_PLACEHOLDER")
        unc_count = sum(1 for f in findings if f.label == "UNCERTAIN")

        with conn:
            cur = conn.execute(
                """
                INSERT INTO scans (
                    scan_target, created_at, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    real_count, placeholder_count, uncertain_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_target,
                    now,
                    len(findings),
                    crit_count,
                    high_count,
                    med_count,
                    low_count,
                    real_count,
                    ph_count,
                    unc_count,
                ),
            )
            scan_id = cur.lastrowid
            assert scan_id is not None

            for f in findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, file, line, secret_type, matched_value_masked,
                        detector_name, pattern_id, label, label_confidence,
                        label_reasons, severity, severity_score, severity_reasoning,
                        context_before, context_after
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        f.file,
                        f.line,
                        f.secret_type,
                        f.masked_value,
                        f.detector_name,
                        f.pattern_id,
                        f.label,
                        f.label_confidence,
                        json.dumps(f.label_reasons),
                        f.severity,
                        f.severity_score,
                        f.severity_reasoning,
                        json.dumps(f.context_before),
                        json.dumps(f.context_after),
                    ),
                )

        return scan_id

    def list_scans(self) -> list[dict[str, Any]]:
        """List all historical scans ordered by most recent first."""
        conn = self.connect()
        cur = conn.execute("SELECT * FROM scans ORDER BY id DESC")
        return [dict(row) for row in cur.fetchall()]

    def get_scan(self, scan_id: int) -> Optional[dict[str, Any]]:
        """Fetch a single scan by ID."""
        conn = self.connect()
        cur = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_findings_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        """Retrieve all findings associated with a scan."""
        conn = self.connect()
        cur = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY severity_score DESC", (scan_id,))
        results: list[dict[str, Any]] = []
        for row in cur.fetchall():
            item = dict(row)
            item["label_reasons"] = json.loads(item["label_reasons"] or "[]")
            item["context_before"] = json.loads(item["context_before"] or "[]")
            item["context_after"] = json.loads(item["context_after"] or "[]")
            results.append(item)
        return results

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and its associated findings."""
        conn = self.connect()
        with conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            return cur.rowcount > 0
