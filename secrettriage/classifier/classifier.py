"""
Real-vs-placeholder classifier.

Takes a Finding (populated by detectors) and adds:
  - label:            LIKELY_REAL | LIKELY_PLACEHOLDER | UNCERTAIN
  - label_confidence: 0–1  (distance from the decision boundary)
  - label_reasons:    list[str] of human-readable evidence strings

Scoring is a weighted additive model starting from a neutral 0.5.
Positive delta → evidence for REAL; negative → evidence for PLACEHOLDER.
All validation is offline (entropy, format, context).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .signals import (
    shannon_entropy,
    char_diversity,
    is_known_placeholder,
    context_keyword_hits,
    filepath_signals,
    repetition_ratio,
    sequential_pattern_score,
    format_validates,
)

if TYPE_CHECKING:
    from secrettriage.detectors.models import Finding

# ── Decision thresholds ───────────────────────────────────────────────────────
_REAL_THRESHOLD        = 0.65   # score >= this → LIKELY_REAL
_PLACEHOLDER_THRESHOLD = 0.35   # score <= this → LIKELY_PLACEHOLDER
# Otherwise → UNCERTAIN

# ── Scoring weights ───────────────────────────────────────────────────────────
_W = {
    "known_placeholder":      -0.50,
    "entropy_very_high":      +0.22,   # > 4.8 bpc
    "entropy_high":           +0.14,   # > 4.0 bpc
    "entropy_medium":         +0.04,   # > 3.2 bpc
    "entropy_low":            -0.12,   # > 2.0 bpc
    "entropy_very_low":       -0.28,   # ≤ 2.0 bpc
    "diversity_4_classes":    +0.10,
    "diversity_3_classes":    +0.05,
    "diversity_1_class":      -0.14,
    "keyword_hit":            -0.15,   # per keyword, capped below
    "keyword_cap":            -0.38,   # maximum keyword penalty
    "fp_placeholder":         -0.13,   # per filepath placeholder signal, capped
    "fp_placeholder_cap":     -0.26,
    "fp_real":                +0.10,   # per filepath real signal, capped
    "fp_real_cap":            +0.18,
    "repetition_high":        -0.32,   # ratio > 0.55
    "repetition_medium":      -0.16,   # ratio > 0.35
    "sequential_high":        -0.24,   # score > 0.55
    "sequential_medium":      -0.12,   # score > 0.35
    "format_valid":           +0.08,
    "format_invalid":         -0.10,
}


def classify(finding: "Finding") -> "Finding":
    """
    Classify *finding* in-place and return it.

    All signals operate offline on the finding's fields:
        matched_value, context_before, context_after, file, secret_type.
    """
    reasons: list[str] = []
    score = 0.5

    value          = finding.matched_value
    all_context    = finding.context_before + finding.context_after
    file_path      = finding.file
    secret_type    = finding.secret_type

    # ── 1. Known-placeholder exact match ─────────────────────────────────────
    if is_known_placeholder(value):
        score += _W["known_placeholder"]
        reasons.append("value matches known documentation placeholder/example list")

    # ── 2. Shannon entropy ───────────────────────────────────────────────────
    h = shannon_entropy(value)
    if h > 4.8:
        score += _W["entropy_very_high"]
        reasons.append(f"high entropy ({h:.2f} bpc) — typical of random secrets")
    elif h > 4.0:
        score += _W["entropy_high"]
        reasons.append(f"above-average entropy ({h:.2f} bpc)")
    elif h > 3.2:
        score += _W["entropy_medium"]
        reasons.append(f"medium entropy ({h:.2f} bpc) — mildly real")
    elif h > 2.0:
        score += _W["entropy_low"]
        reasons.append(f"below-average entropy ({h:.2f} bpc) — mildly suspicious")
    else:
        score += _W["entropy_very_low"]
        reasons.append(f"very low entropy ({h:.2f} bpc) — likely repetitive/placeholder")

    # ── 3. Character-class diversity ─────────────────────────────────────────
    n_classes, present = char_diversity(value)
    if n_classes >= 4:
        score += _W["diversity_4_classes"]
        reasons.append(f"uses all 4 character classes ({', '.join(present)})")
    elif n_classes == 3:
        score += _W["diversity_3_classes"]
        reasons.append(f"uses 3 character classes ({', '.join(present)})")
    elif n_classes == 1:
        score += _W["diversity_1_class"]
        reasons.append(f"uses only 1 character class ({present[0] if present else 'unknown'}) — placeholder-like")

    # ── 4. Context keyword hits ───────────────────────────────────────────────
    kw_hits = context_keyword_hits(all_context, value)
    if kw_hits:
        penalty = max(_W["keyword_cap"], _W["keyword_hit"] * len(kw_hits))
        score += penalty
        reasons.extend(kw_hits[:5])   # cap displayed reasons
        if len(kw_hits) > 5:
            reasons.append(f"… and {len(kw_hits) - 5} more keyword signals")

    # ── 5. File-path signals ─────────────────────────────────────────────────
    ph_fp, real_fp = filepath_signals(file_path)
    if ph_fp:
        penalty = max(_W["fp_placeholder_cap"], _W["fp_placeholder"] * len(ph_fp))
        score += penalty
        reasons.extend(ph_fp[:3])
    if real_fp:
        bonus = min(_W["fp_real_cap"], _W["fp_real"] * len(real_fp))
        score += bonus
        reasons.extend(real_fp[:2])

    # ── 6. Repetition check ──────────────────────────────────────────────────
    rep = repetition_ratio(value)
    if rep > 0.55:
        score += _W["repetition_high"]
        reasons.append(
            f"repetition ratio {rep:.2f} — more than half the string is the same character"
        )
    elif rep > 0.35:
        score += _W["repetition_medium"]
        reasons.append(f"repetition ratio {rep:.2f} — character diversity is low")

    # ── 7. Sequential pattern check ──────────────────────────────────────────
    seq = sequential_pattern_score(value)
    if seq > 0.55:
        score += _W["sequential_high"]
        reasons.append(
            f"sequential pattern score {seq:.2f} — value looks like an alphabet/digit run"
        )
    elif seq > 0.35:
        score += _W["sequential_medium"]
        reasons.append(f"sequential pattern score {seq:.2f} — partial sequential run detected")

    # ── 8. Offline format/checksum validation ────────────────────────────────
    fmt_ok, fmt_reason = format_validates(secret_type, value)
    if fmt_ok is True:
        score += _W["format_valid"]
        reasons.append(fmt_reason)
    elif fmt_ok is False:
        score += _W["format_invalid"]
        reasons.append(f"format check failed: {fmt_reason}")

    # ── 9. Clamp & decide ────────────────────────────────────────────────────
    score = max(0.05, min(0.95, score))
    confidence = abs(score - 0.5) * 2.0   # distance from decision boundary, [0, 0.9]

    if score >= _REAL_THRESHOLD:
        label = "LIKELY_REAL"
    elif score <= _PLACEHOLDER_THRESHOLD:
        label = "LIKELY_PLACEHOLDER"
    else:
        label = "UNCERTAIN"

    finding.label              = label
    finding.label_confidence   = round(confidence, 4)
    finding.label_reasons      = reasons
    return finding
