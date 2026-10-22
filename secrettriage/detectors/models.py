"""
Shared data models for SecretTriage.
All secrets are stored in memory with full value; only masked forms are shown in output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


def _mask(value: str, show: int = 4) -> str:
    """Return a masked representation, showing only the first `show` chars."""
    if len(value) <= show:
        return "*" * len(value)
    return value[:show] + "*" * (len(value) - show)


@dataclass
class Finding:
    """One detected secret occurrence."""

    file: str                        # path to the scanned file (or "<text>" for inline)
    line: int                        # 1-based line number where the match starts
    secret_type: str                 # e.g. "AWS_ACCESS_KEY_ID"
    matched_value: str               # raw matched secret (never shown in output)
    context_before: list[str] = field(default_factory=list)   # lines before the match
    context_after: list[str] = field(default_factory=list)    # lines after the match
    detector_name: str = ""          # name of the detector that fired
    pattern_id: str = ""             # registry key for this pattern

    # Populated by later stages
    label: Optional[str] = None              # LIKELY_REAL / LIKELY_PLACEHOLDER / UNCERTAIN
    label_confidence: float = 0.0
    label_reasons: list[str] = field(default_factory=list)
    severity: Optional[str] = None           # Critical / High / Medium / Low
    severity_score: float = 0.0
    severity_reasoning: str = ""

    @property
    def masked_value(self) -> str:
        return _mask(self.matched_value)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "secret_type": self.secret_type,
            "matched_value_masked": self.masked_value,
            "detector_name": self.detector_name,
            "pattern_id": self.pattern_id,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "label": self.label,
            "label_confidence": self.label_confidence,
            "label_reasons": self.label_reasons,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "severity_reasoning": self.severity_reasoning,
        }
