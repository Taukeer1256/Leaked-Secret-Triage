"""
Stage 2 – Classifier tests.

Tests cover:
  - Individual signal functions (signals.py)
  - End-to-end classify() for edge cases
  - Corpus round-trip (generate + evaluate)
"""
from __future__ import annotations

import math
import pytest

from secrettriage.classifier.signals import (
    shannon_entropy,
    char_diversity,
    is_known_placeholder,
    context_keyword_hits,
    filepath_signals,
    repetition_ratio,
    sequential_pattern_score,
    format_validates,
    KNOWN_PLACEHOLDER_VALUES,
)
from secrettriage.classifier.classifier import classify
from secrettriage.detectors.models import Finding


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _finding(
    value: str,
    secret_type: str = "GENERIC_API_KEY",
    file_path: str = ".env",
    context_before: list[str] | None = None,
    context_after: list[str] | None = None,
) -> Finding:
    return Finding(
        file=file_path,
        line=1,
        secret_type=secret_type,
        matched_value=value,
        context_before=context_before or [],
        context_after=context_after or [],
        detector_name="test",
        pattern_id="test",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # 50/50 split → 1 bit
        assert abs(shannon_entropy("ab") - 1.0) < 1e-9

    def test_high_entropy_random_string(self):
        # A string with all distinct chars should have high entropy
        value = "aAbBcC1234!@#$"
        h = shannon_entropy(value)
        assert h > 3.5

    def test_repetitive_string_low_entropy(self):
        h = shannon_entropy("x" * 40)
        assert h == 0.0

    def test_real_aws_style_entropy(self):
        # AWS secret keys are ~40 random base64 chars
        value = "wJalrXUtnFEMI/K7MDENGbPxRfiCYSyntheticK"
        h = shannon_entropy(value)
        assert h > 4.0

    def test_known_example_entropy(self):
        # AKIAIOSFODNN7EXAMPLE is the AWS docs example — medium entropy
        h = shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        assert 2.5 < h < 5.0   # just verify it's finite and reasonable

    def test_alphabet_sequential_entropy(self):
        h = shannon_entropy("abcdefghijklmnopqrstuvwxyz")
        assert abs(h - math.log2(26)) < 1e-9


# ─────────────────────────────────────────────────────────────────────────────
# Character diversity
# ─────────────────────────────────────────────────────────────────────────────

class TestCharDiversity:
    def test_all_four_classes(self):
        n, classes = char_diversity("Abc1!")
        assert n == 4
        assert set(classes) == {"uppercase", "lowercase", "digit", "symbol"}

    def test_only_uppercase(self):
        n, classes = char_diversity("AKIAIOSFODNN7EXAMPLE")
        # uppercase + digit
        assert n == 2
        assert "uppercase" in classes
        assert "digit" in classes

    def test_only_lowercase(self):
        n, classes = char_diversity("changeme")
        assert n == 1
        assert classes == ["lowercase"]

    def test_digits_only(self):
        n, classes = char_diversity("1234567890")
        assert n == 1
        assert classes == ["digit"]

    def test_mixed_real_secret(self):
        # A realistic mixed-charset secret
        n, _ = char_diversity("wJalrXUtnFEMI/K7MDENG")
        assert n >= 3   # at least upper, lower, symbol


# ─────────────────────────────────────────────────────────────────────────────
# Known-placeholder detection
# ─────────────────────────────────────────────────────────────────────────────

class TestKnownPlaceholder:
    def test_aws_example_key(self):
        assert is_known_placeholder("AKIAIOSFODNN7EXAMPLE")

    def test_aws_example_secret(self):
        assert is_known_placeholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_stripe_example_key(self):
        assert is_known_placeholder("sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc")

    def test_changeme(self):
        assert is_known_placeholder("changeme")

    def test_placeholder(self):
        assert is_known_placeholder("placeholder")

    def test_case_insensitive(self):
        assert is_known_placeholder("CHANGEME")
        assert is_known_placeholder("Placeholder")

    def test_real_looking_value_not_known(self):
        # A high-entropy synthetic value should NOT be in the known list
        assert not is_known_placeholder("AKIAT3LB5XYNTH3T1CKEY0MADEUP1")


# ─────────────────────────────────────────────────────────────────────────────
# Context keyword hits
# ─────────────────────────────────────────────────────────────────────────────

class TestContextKeywords:
    def test_example_keyword(self):
        hits = context_keyword_hits(["# Example configuration"])
        assert any("example" in h for h in hits)

    def test_placeholder_keyword(self):
        hits = context_keyword_hits(["# placeholder value"])
        assert any("placeholder" in h for h in hits)

    def test_changeme(self):
        # Pass as standalone word so \b word-boundary fires correctly
        hits = context_keyword_hits(["changeme"], "")
        assert any("changeme" in h.lower() for h in hits)

    def test_xxx_in_value(self):
        hits = context_keyword_hits([], "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        # Reason contains description of repeated 'x' characters
        assert any("repeated" in h or "x" in h for h in hits)

    def test_your_api_key(self):
        hits = context_keyword_hits(["export API_KEY=your_api_key"])
        assert hits  # should detect something

    def test_todo_keyword(self):
        hits = context_keyword_hits(["# TODO: replace with real token"])
        assert any("TODO" in h.upper() or "todo" in h.lower() for h in hits)

    def test_no_keywords_in_real_context(self):
        hits = context_keyword_hits(["AWS_DEFAULT_REGION=us-east-1", "[credentials]"])
        assert hits == []

    def test_angle_bracket_placeholder(self):
        hits = context_keyword_hits(["api_key = <YOUR_API_KEY>"])
        assert any("angle-bracket" in h or "<" in h for h in hits)

    def test_multiple_keywords_count(self):
        hits = context_keyword_hits(["# Example dummy placeholder for testing"])
        assert len(hits) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# File-path signals
# ─────────────────────────────────────────────────────────────────────────────

class TestFilepathSignals:
    def test_env_is_real_signal(self):
        ph, real = filepath_signals(".env")
        assert any(".env" in r or "env" in r for r in real)

    def test_prod_env_is_real_signal(self):
        _, real = filepath_signals(".env.prod")
        assert real

    def test_tests_dir_is_placeholder_signal(self):
        ph, _ = filepath_signals("tests/test_config.py")
        assert any("tests" in p for p in ph)

    def test_docs_dir_is_placeholder_signal(self):
        ph, _ = filepath_signals("docs/setup.md")
        assert ph

    def test_readme_is_placeholder_signal(self):
        ph, _ = filepath_signals("README.md")
        assert any("README" in p for p in ph)

    def test_pem_file_is_real_signal(self):
        _, real = filepath_signals("secrets/private.pem")
        assert real

    def test_example_in_name_is_placeholder(self):
        ph, _ = filepath_signals("config.example.env")
        assert ph

    def test_neutral_path_returns_empty(self):
        ph, real = filepath_signals("src/main.py")
        assert not ph
        assert not real


# ─────────────────────────────────────────────────────────────────────────────
# Repetition & sequential checks
# ─────────────────────────────────────────────────────────────────────────────

class TestRepetitionAndSequential:
    def test_all_same_char_repetition(self):
        assert repetition_ratio("aaaaaaaaaa") == 1.0

    def test_mixed_low_repetition(self):
        assert repetition_ratio("abcdefghij") < 0.2

    def test_medium_repetition(self):
        r = repetition_ratio("aaabbbccc")
        assert 0.25 < r < 0.5

    def test_sequential_abc(self):
        s = sequential_pattern_score("abcdefghij")
        assert s > 0.8

    def test_sequential_123(self):
        s = sequential_pattern_score("1234567890")
        assert s > 0.8

    def test_random_no_sequential(self):
        s = sequential_pattern_score("Qr7mK2pLxZ")
        assert s < 0.3

    def test_short_string_sequential(self):
        # Short strings always return 0
        assert sequential_pattern_score("ab") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Format validators
# ─────────────────────────────────────────────────────────────────────────────

class TestFormatValidates:
    def test_valid_aws_key(self):
        ok, reason = format_validates("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7ABCD123")
        assert ok is True

    def test_invalid_aws_key_prefix(self):
        ok, reason = format_validates("AWS_ACCESS_KEY_ID", "XXXAIOSFODNN7ABCD123")
        assert ok is False

    def test_valid_github_token(self):
        ok, reason = format_validates("GITHUB_TOKEN", "ghp_" + "A" * 36)
        assert ok is True

    def test_invalid_jwt(self):
        ok, reason = format_validates("JWT", "notajwt")
        assert ok is False

    def test_valid_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        ok, reason = format_validates("JWT", token)
        assert ok is True

    def test_no_validator_for_google(self):
        ok, _ = format_validates("GOOGLE_API_KEY", "AIzaSomething")
        assert ok is None


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end classify() edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestClassify:
    def test_known_placeholder_is_labelled_placeholder(self):
        f = _finding("AKIAIOSFODNN7EXAMPLE", secret_type="AWS_ACCESS_KEY_ID")
        classify(f)
        assert f.label == "LIKELY_PLACEHOLDER"

    def test_high_entropy_real_context_is_real(self):
        # High-entropy value, .env file, neutral context
        value = "wJalrXUtnFEMIsyn7MDEKxR7SyntheticKey"
        f = _finding(value, secret_type="AWS_SECRET_ACCESS_KEY",
                     file_path=".env",
                     context_before=["AWS_ACCESS_KEY_ID=AKIAT3LBSAMPLEKEY1234X"])
        classify(f)
        assert f.label in ("LIKELY_REAL", "UNCERTAIN")

    def test_keyword_context_lowers_confidence(self):
        value = "AKIAT3LBSAMPLEKEY123456"
        f_neutral  = _finding(value, context_before=["AWS_DEFAULT_REGION=us-east-1"])
        f_keyword  = _finding(value, context_before=["# Example - replace with real key"])
        classify(f_neutral)
        classify(f_keyword)
        assert f_keyword.label_confidence <= f_neutral.label_confidence or \
               f_keyword.label != f_neutral.label

    def test_all_x_repetitive_is_placeholder(self):
        value = "ghp_" + "x" * 36
        f = _finding(value, secret_type="GITHUB_TOKEN")
        classify(f)
        assert f.label == "LIKELY_PLACEHOLDER"

    def test_tests_directory_adds_uncertainty(self):
        value = "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0KkXYZW"
        f_prod  = _finding(value, file_path=".env", secret_type="GITHUB_TOKEN")
        f_tests = _finding(value, file_path="tests/conftest.py", secret_type="GITHUB_TOKEN")
        classify(f_prod)
        classify(f_tests)
        # Test directory should reduce score compared to .env
        assert f_tests.label_confidence <= f_prod.label_confidence or \
               f_tests.label in ("LIKELY_PLACEHOLDER", "UNCERTAIN")

    def test_reasons_list_populated(self):
        f = _finding("AKIAIOSFODNN7EXAMPLE", secret_type="AWS_ACCESS_KEY_ID")
        classify(f)
        assert len(f.label_reasons) > 0

    def test_confidence_in_range(self):
        f = _finding("someRandomValue123", secret_type="GENERIC_API_KEY")
        classify(f)
        assert 0.0 <= f.label_confidence <= 1.0

    def test_placeholder_context_overrides_high_entropy(self):
        # Even a high-entropy value labeled 'example' in docs/ should lean placeholder
        import random
        rng = random.Random(99)
        value = "".join(rng.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=40))
        f = _finding(
            value,
            file_path="docs/setup.md",
            context_before=["# Example API key for documentation:", "# Replace with your real key"],
        )
        classify(f)
        # Should either be placeholder or uncertain, not confidently real
        assert f.label in ("LIKELY_PLACEHOLDER", "UNCERTAIN")

    def test_jwt_label_with_none_algorithm(self):
        # JWT with alg:none + placeholder context in docs/ → should NOT be confidently real
        import base64
        header  = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        token = f"{header}.{payload}."
        f = _finding(
            token,
            secret_type="JWT",
            file_path="docs/auth.md",
            context_before=["# Example JWT for documentation", "# Do not use in production"],
        )
        classify(f)
        assert f.label in ("LIKELY_PLACEHOLDER", "UNCERTAIN")

    def test_sequential_value_is_placeholder(self):
        f = _finding("abcdefghijklmnopqrstuvwxyz12345678", secret_type="GENERIC_API_KEY")
        classify(f)
        assert f.label in ("LIKELY_PLACEHOLDER", "UNCERTAIN")

    def test_all_zeros_is_placeholder(self):
        f = _finding("0" * 40, secret_type="AWS_SECRET_ACCESS_KEY")
        classify(f)
        assert f.label == "LIKELY_PLACEHOLDER"

    def test_classify_returns_finding(self):
        f = _finding("someValue12345678", secret_type="GENERIC_API_KEY")
        result = classify(f)
        assert result is f   # in-place modification, same object returned


# ─────────────────────────────────────────────────────────────────────────────
# Corpus round-trip smoke test
# ─────────────────────────────────────────────────────────────────────────────

class TestCorpusRoundTrip:
    """Generate corpus (if needed) and verify classifier achieves acceptable metrics."""

    def _ensure_corpus(self, tmp_path):
        """Generate a small corpus in tmp_path."""
        import sys, pathlib, importlib
        # Run generator
        import subprocess
        result = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).parent.parent / "data" / "generate_corpus.py")],
            capture_output=True, text=True
        )
        return result.returncode == 0

    def test_corpus_generates_successfully(self, tmp_path):
        import subprocess, sys, pathlib
        result = subprocess.run(
            [sys.executable,
             str(pathlib.Path(__file__).parent.parent / "data" / "generate_corpus.py")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"Corpus generator failed:\n{result.stderr}"
        assert "Generated" in result.stdout

    def test_classifier_achieves_acceptable_f1(self):
        """F1 >= 0.75 on the synthetic corpus."""
        import json, pathlib, sys
        corpus_path = pathlib.Path(__file__).parent.parent / "data" / "corpus" / "corpus.jsonl"
        if not corpus_path.exists():
            import subprocess
            subprocess.run(
                [sys.executable, str(pathlib.Path(__file__).parent.parent / "data" / "generate_corpus.py")],
                check=True,
            )

        tp = fp = tn = fn = 0
        with corpus_path.open(encoding="utf-8") as f_:
            for line in f_:
                s = json.loads(line.strip())
                finding = Finding(
                    file=s["file_path"], line=1,
                    secret_type=s["secret_type"],
                    matched_value=s["value"],
                    context_before=s.get("context_before", []),
                    context_after=s.get("context_after", []),
                )
                classify(finding)
                truth, pred = s["label"], finding.label
                if pred == "LIKELY_REAL":
                    if truth == "LIKELY_REAL":         tp += 1
                    else:                              fp += 1
                elif pred == "LIKELY_PLACEHOLDER":
                    if truth == "LIKELY_REAL":         fn += 1
                    else:                              tn += 1
                # UNCERTAIN counted neither as TP/TN nor FP/FN

        precision = tp / (tp + fp) if (tp + fp) else 0
        recall    = tp / (tp + fn) if (tp + fn) else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        print(f"\nCorpus metrics → precision={precision:.2f} recall={recall:.2f} F1={f1:.2f}")
        assert f1 >= 0.75, f"F1={f1:.2f} is below the 0.75 threshold"
