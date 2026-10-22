"""
Stage 4 – Reports Generator tests.

Tests cover:
  - CISO executive report generation (Markdown & HTML)
  - Severity count accuracy & posture determination
  - Top 3 business-impact risks sorting
  - False-positive / noise-reduction audit section
  - Responsible-disclosure draft generation
  - Masked evidence verification (no unmasked secrets in report)
  - Remediation instructions and CVD timeline placeholders
  - Disk output writing
"""
from __future__ import annotations

from pathlib import Path
import pytest

from secrettriage.detectors.models import Finding
from secrettriage.reports import generate_ciso_report, generate_disclosure_draft


def _create_mock_finding(
    secret_type: str,
    severity: str,
    score: float,
    label: str,
    conf: float = 0.95,
    file: str = "src/app.py",
    line: int = 42,
    raw_secret: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
) -> Finding:
    f = Finding(
        file=file,
        line=line,
        secret_type=secret_type,
        matched_value=raw_secret,
        context_before=["# Database initialization", "def init_client():"],
        context_after=["    client.connect()"],
        detector_name=secret_type.replace("_", " ").title(),
        pattern_id=secret_type.lower(),
        label=label,
        label_confidence=conf,
        severity=severity,
        severity_score=score,
        severity_reasoning=f"Base: {score} ({secret_type} - Critical takeover) | Exposed in {file}",
    )
    return f


class TestCisoReport:
    def test_empty_findings_report(self):
        md = generate_ciso_report([])
        assert "SECURE / CLEAN" in md
        assert "Total Findings" in md
        assert "**0**" in md

    def test_critical_posture_and_counts(self):
        findings = [
            _create_mock_finding("AWS_SECRET_ACCESS_KEY", "Critical", 9.5, "LIKELY_REAL", file=".env"),
            _create_mock_finding("GITHUB_TOKEN", "High", 7.8, "LIKELY_REAL", file="ci.yml"),
            _create_mock_finding("STRIPE_PUBLISHABLE_KEY", "Low", 2.0, "LIKELY_REAL", file="client.js"),
            _create_mock_finding("AWS_ACCESS_KEY_ID", "Low", 1.8, "LIKELY_PLACEHOLDER", file="tests/test.py"),
        ]
        md = generate_ciso_report(findings)

        assert "ELEVATED (CRITICAL SECRETS EXPOSED)" in md
        assert "| **Critical** | **1** |" in md
        assert "| **High** | **1** |" in md
        assert "| **Low / Info** | **2** |" in md
        assert "**4**" in md  # total count

    def test_top_3_risks_selection(self):
        findings = [
            _create_mock_finding("GENERIC_PASSWORD", "Medium", 5.5, "LIKELY_REAL", file="db.py"),
            _create_mock_finding("AWS_SECRET_ACCESS_KEY", "Critical", 9.8, "LIKELY_REAL", file=".env"),
            _create_mock_finding("GITHUB_TOKEN", "High", 8.2, "LIKELY_REAL", file="ci.yml"),
            _create_mock_finding("PRIVATE_KEY", "Critical", 9.6, "LIKELY_REAL", file="server.pem"),
            _create_mock_finding("STRIPE_PUBLISHABLE_KEY", "Low", 2.0, "LIKELY_REAL", file="app.js"),
        ]
        md = generate_ciso_report(findings)

        # Top 3 should be AWS_SECRET_ACCESS_KEY (9.8), PRIVATE_KEY (9.6), and GITHUB_TOKEN (8.2)
        assert "1. AWS_SECRET_ACCESS_KEY" in md
        assert "2. PRIVATE_KEY" in md
        assert "3. GITHUB_TOKEN" in md
        assert "STRIPE_PUBLISHABLE_KEY" not in md.split("## 2. Top Business-Impact Risks")[1].split("## 3. Recommended Remediation Plan")[0]

    def test_false_positive_audit_note(self):
        findings = [
            _create_mock_finding("AWS_ACCESS_KEY_ID", "Low", 2.0, "LIKELY_PLACEHOLDER"),
            _create_mock_finding("OPENAI_API_KEY", "Low", 1.5, "LIKELY_PLACEHOLDER"),
        ]
        md = generate_ciso_report(findings)
        assert "filtered/demoted **2** confirmed placeholder/dummy credentials" in md
        assert "avoided **2 false alarms**" in md

    def test_html_export(self, tmp_path: Path):
        findings = [_create_mock_finding("AWS_SECRET_ACCESS_KEY", "Critical", 9.5, "LIKELY_REAL")]
        html_content = generate_ciso_report(findings, to_html=True)

        assert "<!DOCTYPE html>" in html_content
        assert "<style>" in html_content
        assert "AWS_SECRET_ACCESS_KEY" in html_content
        assert "<table>" in html_content

        # Test writing to file
        out_file = tmp_path / "ciso_summary.html"
        generate_ciso_report(findings, output_path=out_file)
        assert out_file.exists()
        assert "<!DOCTYPE html>" in out_file.read_text(encoding="utf-8")


class TestDisclosureDraft:
    def test_disclosure_contains_required_sections(self):
        raw_key = "ghp_RealLookingTokenNotActuallyValid999"
        f = _create_mock_finding(
            secret_type="GITHUB_TOKEN",
            severity="High",
            score=8.0,
            label="LIKELY_REAL",
            file="backend/config.py",
            line=25,
            raw_secret=raw_key,
        )
        draft = generate_disclosure_draft(f, recipient_org="Acme Corp", reporter_name="Security Auditor")

        # Basic metadata
        assert "Acme Corp" in draft
        assert "Security Auditor" in draft
        assert "backend/config.py" in draft
        assert "Line Number**: `25`" in draft

        # Critical: raw key MUST NOT be present; masked key MUST be present
        assert raw_key not in draft
        assert f.masked_value in draft

        # Remediation protocol
        assert "git-filter-repo" in draft
        assert "Credential Rotation" in draft
        assert "Immediate Revocation" in draft

        # Timeline and safe harbor
        assert "Initial Notification" in draft
        assert "Acknowledgment Requested By" in draft
        assert "Public Disclosure Embargo Date" in draft
        assert "Safe Harbor & Non-Exploitation Declaration" in draft

    def test_disclosure_file_write(self, tmp_path: Path):
        f = _create_mock_finding("STRIPE_SECRET_KEY", "Critical", 9.0, "LIKELY_REAL")
        out_file = tmp_path / "disclosure_stripe.md"
        draft = generate_disclosure_draft(f, output_path=out_file)

        assert out_file.exists()
        assert out_file.read_text(encoding="utf-8") == draft
