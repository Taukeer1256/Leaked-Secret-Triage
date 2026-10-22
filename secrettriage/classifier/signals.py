"""
Classifier signal functions.

Each function is a pure, unit-testable transformation of Finding fields.
No network calls, no side effects.
"""
from __future__ import annotations

import math
import re
from typing import NamedTuple


# ─────────────────────────────────────────────────────────────────────────────
# Entropy & character diversity
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def char_diversity(value: str) -> tuple[int, list[str]]:
    """
    Count how many of four character classes appear.
    Returns (count 0-4, list of present class names).
    """
    classes = {
        "uppercase": bool(re.search(r"[A-Z]", value)),
        "lowercase": bool(re.search(r"[a-z]", value)),
        "digit":     bool(re.search(r"[0-9]", value)),
        "symbol":    bool(re.search(r"[^A-Za-z0-9]", value)),
    }
    present = [name for name, found in classes.items() if found]
    return len(present), present


# ─────────────────────────────────────────────────────────────────────────────
# Known-placeholder exact-match list
# Source: official documentation examples, publicly documented fake values.
# These are CANONICAL FAKE VALUES — never real credentials.
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    # AWS documentation canonical examples (published by Amazon)
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # Stripe documentation example keys
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_4eC39HqLyjWDarjtT1zdp7dc",
    # GitHub documentation examples
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    # Generic obvious placeholders
    "your-api-key-here",
    "YOUR_API_KEY_HERE",
    "YOUR_SECRET_KEY_HERE",
    "YOUR_ACCESS_TOKEN_HERE",
    "INSERT_API_KEY_HERE",
    "REPLACE_WITH_YOUR_KEY",
    "ADD_YOUR_API_KEY_HERE",
    "changeme",
    "CHANGEME",
    "change_me",
    "placeholder",
    "PLACEHOLDER",
    "example_key",
    "example_secret",
    "test_key",
    "test_secret",
    "dummy_key",
    "dummy_secret",
    "fake_key",
    "fake_secret",
    "sample_key",
    "sample_secret",
    "my_api_key",
    "my_secret_key",
    "1234567890",
    "0000000000000000000000000000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
})


def is_known_placeholder(value: str) -> bool:
    """Return True if the value exactly matches a documented placeholder."""
    return value in KNOWN_PLACEHOLDER_VALUES or value.lower() in {
        v.lower() for v in KNOWN_PLACEHOLDER_VALUES
    }


# ─────────────────────────────────────────────────────────────────────────────
# Context keyword signals
# ─────────────────────────────────────────────────────────────────────────────

# (regex pattern, human-readable explanation)
_PLACEHOLDER_CONTEXT_PATTERNS: list[tuple[str, str]] = [
    (r"\byour[_\-]?api[_\-]?key\b",   "context contains 'your_api_key' keyword"),
    (r"\byour[_\-]?secret\b",          "context contains 'your_secret' keyword"),
    (r"\byour[_\-]?token\b",           "context contains 'your_token' keyword"),
    (r"\bexample\b",                    "context contains 'example' keyword"),
    (r"\bplaceholder\b",               "context contains 'placeholder' keyword"),
    (r"\bdummy\b",                     "context contains 'dummy' keyword"),
    (r"\bfake\b",                      "context contains 'fake' keyword"),
    (r"\bsample\b",                    "context contains 'sample' keyword"),
    (r"\bchangeme\b",                  "context contains 'changeme'"),
    (r"\bchange[_\-]?me\b",           "context contains 'change_me'"),
    (r"\breplace[_\-]?me\b",          "context contains 'replace_me'"),
    (r"\btodo\b",                      "context contains 'TODO'"),
    (r"\binsert[_\-]?here\b",         "context contains 'insert_here'"),
    (r"\badd[_\-]?your\b",            "context contains 'add_your'"),
    (r"\btest[_\-]?(?:key|secret|token|credential)\b",
                                        "context mentions 'test key/secret/token'"),
    (r"\bdemo\b",                      "context contains 'demo'"),
    (r"\bfixture\b",                   "context contains 'fixture'"),
    (r"\bmock\b",                      "context contains 'mock'"),
    (r"xxx+",                          "context/value has repeated 'x' characters"),
    (r"<[A-Z_]{3,}>",                 "context has angle-bracket placeholder like <API_KEY>"),
    (r"\[?your",                       "context has 'your ...' template marker"),
]


def context_keyword_hits(
    context_lines: list[str],
    matched_value: str = "",
) -> list[str]:
    """
    Return human-readable reasons for every placeholder keyword found in
    context lines (before + after) or in the matched value itself.
    """
    combined = " ".join(context_lines) + " " + matched_value
    hits: list[str] = []
    for pattern, reason in _PLACEHOLDER_CONTEXT_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            hits.append(reason)
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# File-path signals
# ─────────────────────────────────────────────────────────────────────────────

_PLACEHOLDER_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"(?:^|[/\\])tests?[/\\]",     "path is under tests/ directory"),
    (r"(?:^|[/\\])spec[/\\]",       "path is under spec/ directory"),
    (r"(?:^|[/\\])__tests__[/\\]",  "path is under __tests__/ directory"),
    (r"(?:^|[/\\])fixtures?[/\\]",  "path is under fixtures/ directory"),
    (r"(?:^|[/\\])docs?[/\\]",      "path is under docs/ directory"),
    (r"(?:^|[/\\])examples?[/\\]",  "path is under examples/ directory"),
    (r"(?:^|[/\\])mock",            "filename contains 'mock'"),
    (r"README",                      "file is a README"),
    (r"CONTRIBUTING",               "file is CONTRIBUTING"),
    (r"CHANGELOG",                  "file is CHANGELOG"),
    (r"\.md$",                      "file is a markdown document"),
    (r"\.rst$",                     "file is an RST documentation file"),
    (r"sample",                     "filename contains 'sample'"),
    (r"example",                    "filename contains 'example'"),
    (r"template",                   "filename contains 'template'"),
    (r"demo",                       "filename contains 'demo'"),
]

_REAL_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"\.env(?:\.|$)",              "file is a .env file (credentials common)"),
    (r"\.env\.(prod|staging|live)", "file is a production/staging .env"),
    (r"(?:^|[/\\])secrets?[/\\]",  "file is under secrets/ directory"),
    (r"credentials?",              "filename contains 'credentials'"),
    (r"(?:^|[/\\])config[/\\](?:prod|production|staging|live)",
                                   "file is in production config directory"),
    (r"\.pem$",                     "file is a PEM certificate/key file"),
    (r"\.key$",                     "file is a key file"),
    (r"id_rsa",                     "file looks like an SSH private key"),
]


def filepath_signals(file_path: str) -> tuple[list[str], list[str]]:
    """
    Returns (placeholder_reasons, real_reasons).
    """
    placeholder: list[str] = []
    real: list[str] = []
    for pattern, desc in _PLACEHOLDER_PATH_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            placeholder.append(desc)
    for pattern, desc in _REAL_PATH_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            real.append(desc)
    return placeholder, real


# ─────────────────────────────────────────────────────────────────────────────
# Repetition & sequential pattern checks
# ─────────────────────────────────────────────────────────────────────────────

def repetition_ratio(value: str) -> float:
    """Fraction of the string occupied by its most-common character (0–1)."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    return max(freq.values()) / len(value)


def sequential_pattern_score(value: str) -> float:
    """
    Proportion of consecutive (char_i+1 == char_i + 1) pairs.
    Detects runs like 'abcdef' or '123456'.
    Returns 0–1; higher → more sequential.
    """
    if len(value) < 4:
        return 0.0
    runs = sum(
        1 for i in range(1, len(value))
        if ord(value[i]) == ord(value[i - 1]) + 1
    )
    return runs / (len(value) - 1)


# ─────────────────────────────────────────────────────────────────────────────
# Format / checksum validators (offline only)
# ─────────────────────────────────────────────────────────────────────────────

def aws_key_id_valid(value: str) -> bool:
    """AWS key IDs: exactly 20 chars, starts with AKIA/ASIA/AROA/AGPA/AIPA/ANPA/ANVA/APKA."""
    return bool(re.fullmatch(
        r"(?:AKIA|ASIA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}", value
    ))


def github_token_structure_valid(value: str) -> bool:
    """GitHub PAT: known prefix + base62 suffix, correct length."""
    return bool(re.fullmatch(
        r"(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}", value
    ))


def jwt_structure_valid(value: str) -> bool:
    """JWT: three base64url segments separated by dots."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    b64 = re.compile(r"^[A-Za-z0-9_\-]+=*$")
    return all(b64.match(p) for p in parts if p)


_FORMAT_VALIDATORS: dict[str, callable] = {
    "AWS_ACCESS_KEY_ID": aws_key_id_valid,
    "GITHUB_TOKEN": github_token_structure_valid,
    "JWT": jwt_structure_valid,
}


def format_validates(secret_type: str, value: str) -> tuple[bool | None, str]:
    """
    Run the offline format validator for *secret_type*, if one exists.
    Returns (result, reason):
      result=True  → format valid (mild real signal)
      result=False → format invalid (mild placeholder signal)
      result=None  → no validator for this type
    """
    validator = _FORMAT_VALIDATORS.get(secret_type)
    if validator is None:
        return None, "no format validator for this secret type"
    ok = validator(value)
    if ok:
        return True, "passes offline format/structure check"
    return False, "fails offline format/structure check"
