"""
Stage 3 – Severity Scorer tests.

Tests cover:
  - Base score and blast radius resolution across secret types
  - Location risk evaluation (client-side JS, prod configs, CI/CD, test/docs)
  - Classifier demotion (placeholders demoted to Low)
  - Classifier confidence weighting for real secrets
  - Custom weights configuration loading
  - Integration: Detect -> Classify -> Score pipeline
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secrettriage.classifier import classify
from secrettriage.detectors.models import Finding
from secrettriage.detectors.registry import scan_text
from secrettriage.scoring import (
    evaluate_location,
    get_blast_radius,
    load_config,
    score,
    score_all,
)


def _make_finding(
    secret_type: str = "AWS_SECRET_ACCESS_KEY",
    pattern_id: str = "aws_secret_access_key",
    file: str = "src/server.py",
    label: str = "LIKELY_REAL",
    confidence: float = 0.95,
    matched_value: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
) -> Finding:
    """Helper to construct a finding with explicit attributes."""
    f = Finding(
        file=file,
        line=10,
        secret_type=secret_type,
        matched_value=matched_value,
        pattern_id=pattern_id,
    )
    f.label = label
    f.label_confidence = confidence
    return f


class TestBlastRadiusAndBaseScores:
    def test_aws_secret_access_key_is_critical_cloud_root(self):
        f = _make_finding(secret_type="AWS_SECRET_ACCESS_KEY")
        blast = get_blast_radius(f)
        assert "takeover" in blast.lower() or "infrastructure" in blast.lower()
        scored = score(f)
        assert scored.severity == "Critical"
        assert scored.severity_score >= 8.5

    def test_private_key_is_critical(self):
        f = _make_finding(secret_type="PRIVATE_KEY", pattern_id="pem_private_key")
        scored = score(f)
        assert scored.severity == "Critical"
        assert "SSH" in scored.severity_reasoning or "cryptographic" in scored.severity_reasoning

    def test_stripe_publishable_key_is_low(self):
        f = _make_finding(
            secret_type="STRIPE_PUBLISHABLE_KEY",
            pattern_id="stripe_publishable_key",
            file="frontend/src/Checkout.jsx",
        )
        scored = score(f)
        assert scored.severity == "Low"
        assert scored.severity_score <= 3.0
        assert "public" in scored.severity_reasoning.lower()

    def test_pattern_override_github_refresh(self):
        f = _make_finding(
            secret_type="GITHUB_TOKEN",
            pattern_id="github_refresh_token",
        )
        scored = score(f)
        # Refresh token has lower base score (6.0) than classic PAT (8.0)
        assert scored.severity in ("Medium", "High")
        assert "refresh" in scored.severity_reasoning.lower()

    def test_unknown_secret_type_uses_default(self):
        f = _make_finding(secret_type="CUSTOM_PROPRIETARY_TOKEN", pattern_id="custom_id")
        scored = score(f)
        assert "Unclassified" in scored.severity_reasoning


class TestLocationEvaluation:
    def test_client_side_js_boosts_backend_secret(self):
        f = _make_finding(
            secret_type="OPENAI_API_KEY",
            file="public/app.bundle.js",
        )
        scored = score(f)
        assert "client-side" in scored.severity_reasoning.lower()
        # Base 7.5 + 1.5 client modifier = 9.0 * confidence -> Critical or High
        assert scored.severity in ("Critical", "High")

    def test_client_side_js_does_not_penalize_publishable_key(self):
        mod, reasons = evaluate_location("frontend/main.js", "STRIPE_PUBLISHABLE_KEY")
        assert mod == 0.0
        assert any("Expected location" in r for r in reasons)

    def test_production_config_adds_boost(self):
        mod, reasons = evaluate_location(".env.production", "GENERIC_SECRET")
        assert mod >= 1.0
        assert any("environment" in r.lower() or "config" in r.lower() for r in reasons)

    def test_cicd_pipeline_adds_boost(self):
        mod, reasons = evaluate_location(".github/workflows/deploy.yml", "AWS_ACCESS_KEY_ID")
        assert mod >= 0.8
        assert any("ci/cd" in r.lower() for r in reasons)

    def test_test_or_docs_downgrades_severity(self):
        mod, reasons = evaluate_location("tests/fixtures/secrets.json", "AWS_ACCESS_KEY_ID")
        assert mod <= -1.5
        assert any("test" in r.lower() for r in reasons)


class TestClassifierDemotionAndWeighting:
    def test_likely_placeholder_demoted_to_low(self):
        # Even a Critical AWS Secret Key is demoted if it's a placeholder!
        f = _make_finding(
            secret_type="AWS_SECRET_ACCESS_KEY",
            label="LIKELY_PLACEHOLDER",
            confidence=0.99,
        )
        scored = score(f)
        assert scored.severity == "Low"
        assert scored.severity_score <= 2.5
        assert "demotion" in scored.severity_reasoning.lower()

    def test_uncertain_gets_discount(self):
        f_real = _make_finding(secret_type="GITHUB_TOKEN", label="LIKELY_REAL", confidence=0.9)
        f_unc = _make_finding(secret_type="GITHUB_TOKEN", label="UNCERTAIN", confidence=0.5)

        s_real = score(f_real)
        s_unc = score(f_unc)

        assert s_real.severity_score > s_unc.severity_score

    def test_confidence_scaling_for_likely_real(self):
        f_high_conf = _make_finding(confidence=1.0)
        f_low_conf = _make_finding(confidence=0.2)

        s_high = score(f_high_conf)
        s_low = score(f_low_conf)

        assert s_high.severity_score >= s_low.severity_score


class TestCustomConfigAndBatch:
    def test_custom_config_loading(self, tmp_path: Path):
        custom_cfg = {
            "secret_types": {
                "TEST_TYPE": {"base_score": 10.0, "blast_radius": "Armageddon"}
            },
            "location_modifiers": {},
            "classifier_modifiers": {
                "LIKELY_REAL": {"base_factor": 1.0, "confidence_factor": 0.0}
            },
            "severity_thresholds": {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 0.0},
        }
        cfg_file = tmp_path / "custom_weights.json"
        cfg_file.write_text(json.dumps(custom_cfg), encoding="utf-8")

        f = _make_finding(secret_type="TEST_TYPE", label="LIKELY_REAL")
        scored = score(f, config_path=cfg_file)
        assert scored.severity == "Critical"
        assert scored.severity_score == 10.0
        assert "Armageddon" in scored.severity_reasoning

    def test_score_all_batch(self):
        findings = [
            _make_finding(secret_type="AWS_ACCESS_KEY_ID"),
            _make_finding(secret_type="STRIPE_PUBLISHABLE_KEY"),
        ]
        scored_list = score_all(findings)
        assert len(scored_list) == 2
        assert scored_list[0].severity == "Critical"
        assert scored_list[1].severity == "Low"


class TestEndToEndPipeline:
    def test_scan_classify_score_pipeline(self):
        raw_code = """
        # Deployment environment configuration
        AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
        AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """
        findings = scan_text(raw_code, source=".env.production")
        assert len(findings) >= 2

        # Run classifier
        for f in findings:
            classify(f)

        # Run scorer
        score_all(findings)

        for f in findings:
            assert f.severity in ("Critical", "High", "Medium", "Low")
            assert f.severity_score > 0.0
            assert len(f.severity_reasoning) > 0

            # Verify to_dict output contains full audit trail
            d = f.to_dict()
            assert d["severity"] == f.severity
            assert d["severity_score"] == f.severity_score
            assert d["severity_reasoning"] == f.severity_reasoning
