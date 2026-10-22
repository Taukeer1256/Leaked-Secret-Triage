"""
Severity scorer for SecretTriage (Stage 3).

Scores findings based on:
  1. Secret type & blast radius (e.g. cloud root vs read-only API)
  2. Exposure location (client-side JS, production config, CI/CD, tests/docs)
  3. Classifier label and confidence (demoting placeholders, weighting real secrets)

All weights and thresholds are maintained in secrettriage/scoring/weights.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from secrettriage.detectors.models import Finding

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "weights.json"
_CONFIG_CACHE: Optional[dict[str, Any]] = None


def load_config(config_path: Optional[str | Path] = None) -> dict[str, Any]:
    """Load scoring rules and weights from JSON configuration."""
    global _CONFIG_CACHE
    target = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
    if not config_path and _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not config_path:
        _CONFIG_CACHE = data
    return data


def get_blast_radius(finding: "Finding", config: Optional[dict[str, Any]] = None) -> str:
    """Retrieve the blast radius description for a given finding."""
    cfg = config or load_config()
    secret_types = cfg.get("secret_types", {})
    overrides = cfg.get("pattern_overrides", {})

    if finding.pattern_id in overrides and "blast_radius" in overrides[finding.pattern_id]:
        return str(overrides[finding.pattern_id]["blast_radius"])

    if finding.secret_type in secret_types:
        return str(secret_types[finding.secret_type].get("blast_radius", ""))

    return str(secret_types.get("DEFAULT", {}).get("blast_radius", "Unclassified credential exposure"))


def evaluate_location(
    file_path: str,
    secret_type: str,
    config: Optional[dict[str, Any]] = None,
) -> tuple[float, list[str]]:
    """
    Evaluate file path for exposure risk modifiers.

    Returns:
        (total_modifier, list_of_reasons)
    """
    cfg = config or load_config()
    loc_cfg = cfg.get("location_modifiers", {})
    norm_path = file_path.replace("\\", "/").lower()

    modifier = 0.0
    reasons: list[str] = []

    # 1. Test or documentation path (downgrade)
    test_cfg = loc_cfg.get("test_or_docs", {})
    test_patterns = test_cfg.get("patterns", [])
    is_test_or_docs = any(pat in norm_path for pat in test_patterns)

    if is_test_or_docs:
        mod = float(test_cfg.get("modifier", -2.0))
        modifier += mod
        reasons.append(f"Location modifier {mod:+.1f} (in test/docs/fixture: '{file_path}')")
        return modifier, reasons  # Test context takes precedence over client/prod exposure

    # 2. Client-side frontend / JS files
    client_cfg = loc_cfg.get("client_side_js", {})
    client_patterns = client_cfg.get("patterns", [])
    is_client_side = any(norm_path.endswith(pat) or pat in norm_path for pat in client_patterns)

    if is_client_side:
        # Publishable keys are expected in frontend code; backend secrets are critical leaks
        if secret_type == "STRIPE_PUBLISHABLE_KEY":
            reasons.append(f"Expected location for publishable key (client-side: '{file_path}')")
        else:
            mod = float(client_cfg.get("modifier", 1.5))
            modifier += mod
            reasons.append(f"Location modifier {mod:+.1f} (exposed in client-side code: '{file_path}')")

    # 3. Production config / environment files
    prod_cfg = loc_cfg.get("production_config", {})
    prod_patterns = prod_cfg.get("patterns", [])
    is_prod_config = any(pat in norm_path for pat in prod_patterns)

    if is_prod_config:
        mod = float(prod_cfg.get("modifier", 1.0))
        modifier += mod
        reasons.append(f"Location modifier {mod:+.1f} (exposed in environment/deployment config: '{file_path}')")

    # 4. CI/CD pipeline
    cicd_cfg = loc_cfg.get("cicd_pipeline", {})
    cicd_patterns = cicd_cfg.get("patterns", [])
    is_cicd = any(pat in norm_path for pat in cicd_patterns)

    if is_cicd:
        mod = float(cicd_cfg.get("modifier", 0.8))
        modifier += mod
        reasons.append(f"Location modifier {mod:+.1f} (exposed in CI/CD pipeline: '{file_path}')")

    return modifier, reasons


def score(finding: "Finding", config_path: Optional[str | Path] = None) -> "Finding":
    """
    Score severity for a Finding and populate severity, severity_score, severity_reasoning.
    """
    cfg = load_config(config_path)
    secret_types = cfg.get("secret_types", {})
    overrides = cfg.get("pattern_overrides", {})
    thresholds = cfg.get("severity_thresholds", {"Critical": 8.5, "High": 6.5, "Medium": 4.0, "Low": 0.0})
    classifier_mods = cfg.get("classifier_modifiers", {})

    # 1. Base Score & Blast Radius
    type_info = secret_types.get(finding.secret_type, secret_types.get("DEFAULT", {"base_score": 5.0}))
    base_score = float(type_info.get("base_score", 5.0))
    blast_radius = get_blast_radius(finding, cfg)

    # Check for pattern-specific base score override
    if finding.pattern_id in overrides and "base_score" in overrides[finding.pattern_id]:
        base_score = float(overrides[finding.pattern_id]["base_score"])

    reasoning_parts: list[str] = [
        f"Base Score: {base_score:.1f} ({finding.secret_type} - {blast_radius})"
    ]

    # 2. Exposure Location Modifier
    loc_mod, loc_reasons = evaluate_location(finding.file, finding.secret_type, cfg)
    interim_score = base_score + loc_mod
    reasoning_parts.extend(loc_reasons)

    # 3. Classifier Confidence & Label Adjustment
    label = finding.label or "UNCERTAIN"
    conf = finding.label_confidence

    if label == "LIKELY_PLACEHOLDER":
        ph_cfg = classifier_mods.get("LIKELY_PLACEHOLDER", {"max_score": 2.5, "multiplier": 0.2})
        mult = float(ph_cfg.get("multiplier", 0.2))
        max_s = float(ph_cfg.get("max_score", 2.5))
        final_score = min(max_s, interim_score * mult)
        reasoning_parts.append(
            f"Classifier Demotion: Identified as LIKELY_PLACEHOLDER (conf: {conf:.2f}). Score reduced to {final_score:.1f}"
        )
    elif label == "LIKELY_REAL":
        real_cfg = classifier_mods.get("LIKELY_REAL", {"base_factor": 0.85, "confidence_factor": 0.15})
        b_fac = float(real_cfg.get("base_factor", 0.85))
        c_fac = float(real_cfg.get("confidence_factor", 0.15))
        factor = b_fac + (c_fac * conf)
        final_score = interim_score * factor
        reasoning_parts.append(
            f"Classifier Weight: LIKELY_REAL (conf: {conf:.2f}, factor: {factor:.2f})"
        )
    else:  # UNCERTAIN or unclassified
        unc_cfg = classifier_mods.get("UNCERTAIN", {"multiplier": 0.85})
        mult = float(unc_cfg.get("multiplier", 0.85))
        final_score = interim_score * mult
        reasoning_parts.append(
            f"Classifier Adjustment: UNCERTAIN (conf: {conf:.2f}, multiplier: {mult:.2f})"
        )

    # Clamp score to [0.0, 10.0]
    final_score = max(0.0, min(10.0, final_score))
    rounded_score = round(final_score, 1)

    # 4. Severity Mapping
    if rounded_score >= thresholds.get("Critical", 8.5):
        severity = "Critical"
    elif rounded_score >= thresholds.get("High", 6.5):
        severity = "High"
    elif rounded_score >= thresholds.get("Medium", 4.0):
        severity = "Medium"
    else:
        severity = "Low"

    reasoning_parts.append(f"Final Score: {rounded_score}/10.0 -> Severity: {severity}")

    finding.severity = severity
    finding.severity_score = rounded_score
    finding.severity_reasoning = " | ".join(reasoning_parts)

    return finding


def score_all(findings: list["Finding"], config_path: Optional[str | Path] = None) -> list["Finding"]:
    """Score a collection of findings."""
    return [score(f, config_path=config_path) for f in findings]
