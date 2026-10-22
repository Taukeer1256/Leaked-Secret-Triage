"""
Scanner / registry façade.

scan_text()  – scan a string, return list[Finding]
scan_file()  – scan a file on disk, return list[Finding]
REGISTRY     – the loaded PatternDef dict (re-exported for callers)
"""
from __future__ import annotations

import pathlib
from typing import Optional

from .models import Finding
from .patterns import PATTERN_REGISTRY, PatternDef

REGISTRY = PATTERN_REGISTRY

# Number of context lines to capture above/below each match
_CONTEXT_LINES = 2


def scan_text(
    text: str,
    source: str = "<text>",
    pattern_ids: Optional[list[str]] = None,
) -> list[Finding]:
    """
    Scan *text* with all (or a subset of) registered patterns.

    Args:
        text:        Raw text to scan.
        source:      Label used as the ``file`` field in returned Findings.
        pattern_ids: If given, only these pattern IDs are applied.

    Returns:
        List of Finding objects (full matched_value in memory, never printed).
    """
    lines = text.splitlines()
    findings: list[Finding] = []
    patterns = _select_patterns(pattern_ids)

    for pat in patterns:
        for m in pat.pattern.finditer(text):
            raw_value = m.group(pat.group)

            # Skip if the pattern has a structural validator and it fails
            if pat.validator and not pat.validator(raw_value):
                continue

            # Determine 1-based line number of the match start
            line_no = text.count("\n", 0, m.start()) + 1

            # Gather surrounding context lines (0-based index)
            idx = line_no - 1
            before = lines[max(0, idx - _CONTEXT_LINES): idx]
            after = lines[idx + 1: idx + 1 + _CONTEXT_LINES]

            findings.append(
                Finding(
                    file=source,
                    line=line_no,
                    secret_type=pat.secret_type,
                    matched_value=raw_value,
                    context_before=before,
                    context_after=after,
                    detector_name=pat.name,
                    pattern_id=pat.id,
                )
            )

    return findings


def scan_file(
    path: str | pathlib.Path,
    pattern_ids: Optional[list[str]] = None,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> list[Finding]:
    """
    Read a file and scan its contents.

    Args:
        path:        Path to the file.
        pattern_ids: Subset of pattern IDs to apply (None = all).
        encoding:    File encoding (default utf-8).
        errors:      How to handle decode errors.

    Returns:
        List of Finding objects tagged with the real file path.
    """
    p = pathlib.Path(path)
    text = p.read_text(encoding=encoding, errors=errors)
    return scan_text(text, source=str(p), pattern_ids=pattern_ids)


def scan_directory(
    dir_path: str | pathlib.Path,
    pattern_ids: Optional[list[str]] = None,
    max_file_size_kb: int = 1024,
    ignore_dirs: Optional[set[str]] = None,
) -> list[Finding]:
    """
    Recursively scan text files within a directory.

    Skips hidden directories, version control, build caches, and large binary files.
    """
    default_ignores = {
        ".git", ".svn", ".hg", "__pycache__", ".pytest_cache",
        "node_modules", ".venv", "venv", "dist", "build", ".idea", ".vscode"
    }
    ignores = default_ignores if ignore_dirs is None else ignore_dirs

    root = pathlib.Path(dir_path)
    if not root.exists() or not root.is_dir():
        return []

    findings: list[Finding] = []
    max_bytes = max_file_size_kb * 1024

    for p in root.rglob("*"):
        if p.is_file():
            # Check directory components
            if any(part in ignores for part in p.parts):
                continue
            try:
                if p.stat().st_size > max_bytes:
                    continue
                findings.extend(scan_file(p, pattern_ids=pattern_ids))
            except (UnicodeDecodeError, PermissionError, OSError):
                continue

    return findings


# ─────────────────────────────────────────────────────────────────────────────

def _select_patterns(pattern_ids: Optional[list[str]]) -> list[PatternDef]:
    if pattern_ids is None:
        return list(REGISTRY.values())
    return [REGISTRY[pid] for pid in pattern_ids if pid in REGISTRY]
