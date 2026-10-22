"""
Stage 5 – Storage & Pipeline tests.

Tests cover:
  - SQLite database schema initialization
  - Saving scan sessions and findings
  - Zero-leak verification (raw unmasked secret is never persisted to SQLite)
  - Historical scan listing, fetching, and deletion
  - Directory recursive scanning (scan_directory)
"""
from __future__ import annotations

from pathlib import Path
import pytest

from secrettriage.detectors.models import Finding
from secrettriage.detectors.registry import scan_directory
from secrettriage.storage.db import Database


def _create_mock_finding(
    raw_secret: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    secret_type: str = "AWS_SECRET_ACCESS_KEY",
    severity: str = "Critical",
    score: float = 9.5,
    label: str = "LIKELY_REAL",
) -> Finding:
    f = Finding(
        file="src/config.py",
        line=12,
        secret_type=secret_type,
        matched_value=raw_secret,
        context_before=["# config setup"],
        context_after=["print('ready')"],
        detector_name="AWS Secret Access Key",
        pattern_id="aws_secret_access_key",
        label=label,
        label_confidence=0.98,
        label_reasons=["High Shannon entropy (4.85)", "Mixed character classes"],
        severity=severity,
        severity_score=score,
        severity_reasoning="Critical infrastructure impact",
    )
    return f


class TestStorageDatabase:
    def test_schema_init_and_context_manager(self, tmp_path: Path):
        db_file = tmp_path / "test.db"
        with Database(db_file) as db:
            scans = db.list_scans()
            assert scans == []

    def test_save_and_retrieve_scan(self, tmp_path: Path):
        db_file = tmp_path / "test.db"
        raw_secret = "sk_test_51M00000000000000SyntheticRealFormatKeyABC1234567890XYZ"
        f = _create_mock_finding(
            raw_secret=raw_secret,
            secret_type="STRIPE_SECRET_KEY",
            severity="Critical",
            score=9.2,
            label="LIKELY_REAL",
        )

        with Database(db_file) as db:
            scan_id = db.save_scan("repo_scan_target", [f])
            assert scan_id == 1

            # Check scan metadata
            scan = db.get_scan(scan_id)
            assert scan is not None
            assert scan["scan_target"] == "repo_scan_target"
            assert scan["total_findings"] == 1
            assert scan["critical_count"] == 1
            assert scan["real_count"] == 1

            # Check findings
            findings_data = db.get_findings_for_scan(scan_id)
            assert len(findings_data) == 1
            f_row = findings_data[0]
            assert f_row["secret_type"] == "STRIPE_SECRET_KEY"
            assert f_row["severity"] == "Critical"
            assert f_row["severity_score"] == 9.2

            # ZERO-LEAK VERIFICATION: raw secret must NOT be in DB, masked secret MUST be in DB
            assert f_row["matched_value_masked"] == f.masked_value
            assert raw_secret not in f_row["matched_value_masked"]

            # Check JSON deserialization of reasons and contexts
            assert isinstance(f_row["label_reasons"], list)
            assert isinstance(f_row["context_before"], list)

    def test_zero_leak_raw_file_scan(self, tmp_path: Path):
        """Ensure full DB binary/text does not contain raw secrets."""
        db_file = tmp_path / "audit.db"
        super_secret = "VERY_CONFIDENTIAL_SYNTHETIC_TOKEN_12345"
        f = _create_mock_finding(raw_secret=super_secret)

        with Database(db_file) as db:
            db.save_scan("test_leak", [f])

        # Read the raw SQLite database bytes
        raw_db_bytes = db_file.read_bytes()
        assert super_secret.encode("utf-8") not in raw_db_bytes
        # Masked value should be present
        assert f.masked_value.encode("utf-8") in raw_db_bytes

    def test_delete_scan_cascades(self, tmp_path: Path):
        db_file = tmp_path / "test.db"
        f = _create_mock_finding()

        with Database(db_file) as db:
            scan_id = db.save_scan("to_delete", [f])
            assert len(db.list_scans()) == 1
            assert len(db.get_findings_for_scan(scan_id)) == 1

            deleted = db.delete_scan(scan_id)
            assert deleted is True
            assert len(db.list_scans()) == 0
            assert len(db.get_findings_for_scan(scan_id)) == 0


class TestScanDirectory:
    def test_scan_directory_finds_secrets(self, tmp_path: Path):
        sub_dir = tmp_path / "backend"
        sub_dir.mkdir()
        env_file = sub_dir / ".env"
        env_file.write_text(
            'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
            encoding="utf-8",
        )

        findings = scan_directory(tmp_path)
        assert len(findings) >= 2
        types = {f.secret_type for f in findings}
        assert "AWS_ACCESS_KEY_ID" in types
        assert "AWS_SECRET_ACCESS_KEY" in types

    def test_scan_directory_skips_ignored(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        secret_file = git_dir / "config"
        secret_file.write_text('AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

        findings = scan_directory(tmp_path)
        assert findings == []
