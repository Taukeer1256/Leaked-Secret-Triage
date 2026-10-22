"""
Stage 1 – Detector tests.

All secret values used here are SYNTHETIC – generated to match real formats
but never valid/real credentials. See README §Ethics for full disclosure.
"""
from __future__ import annotations

import pytest

from secrettriage.detectors.registry import scan_text, scan_file
from secrettriage.detectors.models import Finding


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find(results: list[Finding], secret_type: str) -> list[Finding]:
    return [f for f in results if f.secret_type == secret_type]


def _one(results: list[Finding], secret_type: str) -> Finding:
    hits = _find(results, secret_type)
    assert hits, f"No finding with secret_type={secret_type!r}"
    return hits[0]


# ─────────────────────────────────────────────────────────────────────────────
# AWS
# ─────────────────────────────────────────────────────────────────────────────

class TestAWSAccessKey:
    # SYNTHETIC key: correct prefix + length, never a real credential.
    SAMPLE_KEY = "AKIAIOSFODNN7ABCD123"   # 20 chars, AKIA prefix

    def test_detects_in_env_assignment(self):
        text = f"AWS_ACCESS_KEY_ID={self.SAMPLE_KEY}"
        results = scan_text(text)
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert hit.matched_value == self.SAMPLE_KEY

    def test_detects_inline(self):
        text = f"key = '{self.SAMPLE_KEY}'"
        results = scan_text(text)
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert self.SAMPLE_KEY in hit.matched_value

    def test_masked_value_hides_secret(self):
        text = f"AWS_ACCESS_KEY_ID={self.SAMPLE_KEY}"
        results = scan_text(text)
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert self.SAMPLE_KEY not in hit.masked_value
        assert hit.masked_value.startswith("AKIA")

    def test_invalid_prefix_rejected(self):
        # Should NOT match – wrong prefix (XXXX is not a valid AWS prefix)
        text = "key=XXXXIOSFODNN7ABCD123"
        results = scan_text(text, pattern_ids=["aws_access_key_id"])
        assert not _find(results, "AWS_ACCESS_KEY_ID")

    def test_too_short_rejected(self):
        text = "key=AKIASHORT"
        results = scan_text(text, pattern_ids=["aws_access_key_id"])
        assert not _find(results, "AWS_ACCESS_KEY_ID")

    def test_line_number_correct(self):
        text = "# comment\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCD123\n# end"
        results = scan_text(text, pattern_ids=["aws_access_key_id"])
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert hit.line == 2


class TestAWSSecretKey:
    # SYNTHETIC: 40 base64 chars
    SAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    def test_detects_env_style(self):
        text = f"aws_secret_access_key={self.SAMPLE_SECRET}"
        results = scan_text(text, pattern_ids=["aws_secret_access_key"])
        hit = _one(results, "AWS_SECRET_ACCESS_KEY")
        assert hit.matched_value == self.SAMPLE_SECRET

    def test_detects_yaml_style(self):
        text = f"aws_secret: '{self.SAMPLE_SECRET}'"
        results = scan_text(text, pattern_ids=["aws_secret_access_key"])
        hit = _one(results, "AWS_SECRET_ACCESS_KEY")
        assert hit.matched_value == self.SAMPLE_SECRET


# ─────────────────────────────────────────────────────────────────────────────
# GitHub tokens
# ─────────────────────────────────────────────────────────────────────────────

class TestGitHubTokens:
    # SYNTHETIC PATs: correct prefix + length, structurally valid, never real.
    # GitHub classic/oauth/server tokens: prefix_ + exactly 36 alphanumeric chars.
    CLASSIC_PAT = "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0KkXYZW"   # 36 chars suffix
    OAUTH_TOKEN = "gho_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0KkXYZW"
    FG_PAT = "github_pat_" + "A" * 11 + "B" * 71                       # 82 chars suffix
    SERVER_TOKEN = "ghs_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0KkXYZW"

    def test_classic_pat(self):
        results = scan_text(f"token: {self.CLASSIC_PAT}", pattern_ids=["github_pat_classic"])
        hit = _one(results, "GITHUB_TOKEN")
        assert hit.matched_value == self.CLASSIC_PAT

    def test_oauth_token(self):
        results = scan_text(f"GITHUB_TOKEN={self.OAUTH_TOKEN}", pattern_ids=["github_oauth_token"])
        hit = _one(results, "GITHUB_TOKEN")
        assert hit.matched_value == self.OAUTH_TOKEN

    def test_fine_grained_pat(self):
        results = scan_text(f"auth: {self.FG_PAT}", pattern_ids=["github_fine_grained_pat"])
        hit = _one(results, "GITHUB_TOKEN")
        assert hit.matched_value == self.FG_PAT

    def test_server_to_server(self):
        results = scan_text(f"bearer {self.SERVER_TOKEN}", pattern_ids=["github_server_to_server"])
        hit = _one(results, "GITHUB_TOKEN")
        assert hit.matched_value == self.SERVER_TOKEN

    def test_short_token_rejected(self):
        results = scan_text("token: ghp_short", pattern_ids=["github_pat_classic"])
        assert not _find(results, "GITHUB_TOKEN")


# ─────────────────────────────────────────────────────────────────────────────
# Google API Key
# ─────────────────────────────────────────────────────────────────────────────

class TestGoogleAPIKey:
    # SYNTHETIC: AIza + 35 alphanum chars
    SAMPLE = "AIzaSyD-9tSrke72I6e68pqO8SYNTHETIC_FAKE"

    def test_detects(self):
        results = scan_text(f"GOOGLE_API_KEY={self.SAMPLE}", pattern_ids=["google_api_key"])
        hit = _one(results, "GOOGLE_API_KEY")
        assert hit.matched_value == self.SAMPLE

    def test_wrong_prefix_rejected(self):
        results = scan_text("key=BIzaSyD-9tSrke72I6e68pqO8ABCDEFGHIJKL", pattern_ids=["google_api_key"])
        assert not _find(results, "GOOGLE_API_KEY")


# ─────────────────────────────────────────────────────────────────────────────
# Slack tokens
# ─────────────────────────────────────────────────────────────────────────────

class TestSlackTokens:
    BOT   = "xoxb-" + "12345678901-12345678901-aAbBcCdDeEfFgGhHiIjJkKlL"
    USER  = "xoxp-" + "12345678901-12345678901-09876543210-aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP"

    def test_bot_token(self):
        results = scan_text(f"SLACK_TOKEN={self.BOT}", pattern_ids=["slack_bot_token"])
        hit = _one(results, "SLACK_TOKEN")
        assert hit.matched_value == self.BOT

    def test_user_token(self):
        results = scan_text(f"token={self.USER}", pattern_ids=["slack_user_token"])
        hit = _one(results, "SLACK_TOKEN")
        assert hit.matched_value == self.USER


# ─────────────────────────────────────────────────────────────────────────────
# Stripe keys
# ─────────────────────────────────────────────────────────────────────────────

class TestStripeKeys:
    # SYNTHETIC: sk_live_ prefix + 24 random chars (total > 32)
    SECRET  = "sk_" + "live_FakeSyntheticKey1234567890ABCDEFGHIJKLMNOPxyz"
    TEST_SK = "sk_test_FakeSyntheticKey1234567890ABCDEFGHIJKLMNOPxyz"
    PK      = "pk_live_FakeSyntheticKey1234567890ABCDEFGHIJKLMNOPxyz"

    def test_live_secret_key(self):
        results = scan_text(f"STRIPE_KEY={self.SECRET}", pattern_ids=["stripe_secret_key"])
        hit = _one(results, "STRIPE_SECRET_KEY")
        assert "sk_live_" in hit.matched_value

    def test_test_secret_key(self):
        results = scan_text(f"key={self.TEST_SK}", pattern_ids=["stripe_secret_key"])
        hit = _one(results, "STRIPE_SECRET_KEY")
        assert "sk_test_" in hit.matched_value

    def test_publishable_key_lower_severity(self):
        results = scan_text(f"key={self.PK}", pattern_ids=["stripe_publishable_key"])
        hit = _one(results, "STRIPE_PUBLISHABLE_KEY")
        from secrettriage.detectors.patterns import PATTERN_REGISTRY
        assert PATTERN_REGISTRY["stripe_publishable_key"].base_severity == "Low"


# ─────────────────────────────────────────────────────────────────────────────
# JWT
# ─────────────────────────────────────────────────────────────────────────────

class TestJWT:
    # SYNTHETIC: valid base64url structure, header/payload/signature – never real
    TOKEN = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlN5bnRoZXRpYyIsImlhdCI6MTV9"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_detects_jwt(self):
        results = scan_text(f"Authorization: Bearer {self.TOKEN}", pattern_ids=["jwt_token"])
        hit = _one(results, "JWT")
        assert hit.matched_value == self.TOKEN

    def test_not_a_jwt_rejected(self):
        results = scan_text("eyJfake", pattern_ids=["jwt_token"])
        assert not _find(results, "JWT")


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI / Anthropic
# ─────────────────────────────────────────────────────────────────────────────

class TestOpenAI:
    # SYNTHETIC: contains the T3BlbkFJ marker that all real OpenAI keys have.
    # sk-proj- prefix + >=20 chars + T3BlbkFJ marker + >=20 chars (never a real key)
    KEY = "sk-proj-" + "FakeSyntheticKey12345T3BlbkFJFakeSynthetic1234567890abcdef"

    def test_detects_openai(self):
        results = scan_text(f"OPENAI_API_KEY={self.KEY}", pattern_ids=["openai_api_key"])
        hit = _one(results, "OPENAI_API_KEY")
        assert "T3BlbkFJ" in hit.matched_value


class TestAnthropic:
    # SYNTHETIC: sk-ant-api03- prefix + 80+ chars
    KEY = "sk-ant-api03-" + "A" * 93

    def test_detects_anthropic(self):
        results = scan_text(f"ANTHROPIC_API_KEY={self.KEY}", pattern_ids=["anthropic_api_key"])
        hit = _one(results, "ANTHROPIC_API_KEY")
        assert hit.matched_value.startswith("sk-ant-")


# ─────────────────────────────────────────────────────────────────────────────
# Private Key Headers
# ─────────────────────────────────────────────────────────────────────────────

class TestPrivateKeyHeaders:
    RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
    EC_HEADER  = "-----BEGIN EC PRIVATE KEY-----"
    OPENSSH    = "-----BEGIN OPENSSH PRIVATE KEY-----"
    PKCS8      = "-----BEGIN PRIVATE KEY-----"

    @pytest.mark.parametrize("header", [RSA_HEADER, EC_HEADER, OPENSSH])
    def test_pem_header_detected(self, header):
        results = scan_text(f"\n{header}\nMIIEp...\n", pattern_ids=["pem_private_key"])
        hit = _one(results, "PRIVATE_KEY")
        assert hit.matched_value == header

    def test_pkcs8_detected(self):
        results = scan_text(f"{self.PKCS8}\nMIIEvg...", pattern_ids=["pkcs8_private_key"])
        hit = _one(results, "PRIVATE_KEY")
        assert "PRIVATE KEY" in hit.matched_value


# ─────────────────────────────────────────────────────────────────────────────
# Generic assignment patterns
# ─────────────────────────────────────────────────────────────────────────────

class TestGenericAssignments:
    def test_api_key_equals(self):
        results = scan_text('api_key = "abcdef1234567890abcdef12"', pattern_ids=["generic_api_key_assignment"])
        hit = _one(results, "GENERIC_API_KEY")
        assert "abcdef" in hit.matched_value

    def test_api_key_colon(self):
        results = scan_text("apikey: abcdef1234567890abcdef12", pattern_ids=["generic_api_key_assignment"])
        hit = _one(results, "GENERIC_API_KEY")
        assert hit is not None

    def test_secret_key(self):
        results = scan_text('secret_key = "my-super-secret-key-value12345"', pattern_ids=["generic_secret_assignment"])
        hit = _one(results, "GENERIC_SECRET")
        assert hit is not None

    def test_password_assignment(self):
        results = scan_text('password = "S3cur3P@ssw0rd!"', pattern_ids=["generic_password_assignment"])
        hit = _one(results, "GENERIC_PASSWORD")
        assert hit is not None

    def test_access_token(self):
        results = scan_text('access_token = "ya29.FakeSynthetToken1234567890"', pattern_ids=["generic_token_assignment"])
        hit = _one(results, "GENERIC_TOKEN")
        assert hit is not None


# ─────────────────────────────────────────────────────────────────────────────
# Context lines
# ─────────────────────────────────────────────────────────────────────────────

class TestContextCapture:
    def test_two_lines_before_and_after(self):
        text = "\n".join([
            "line1",
            "line2",
            "AKIAIOSFODNN7ABCD123",
            "line4",
            "line5",
        ])
        results = scan_text(text, pattern_ids=["aws_access_key_id"])
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert "line1" in hit.context_before
        assert "line2" in hit.context_before
        assert "line4" in hit.context_after
        assert "line5" in hit.context_after

    def test_context_at_file_start(self):
        text = "AKIAIOSFODNN7ABCD123\nline2\nline3"
        results = scan_text(text, pattern_ids=["aws_access_key_id"])
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert hit.context_before == []


# ─────────────────────────────────────────────────────────────────────────────
# scan_file
# ─────────────────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_scan_temp_file(self, tmp_path):
        f = tmp_path / "test.env"
        f.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCD123\n")
        results = scan_file(str(f), pattern_ids=["aws_access_key_id"])
        hit = _one(results, "AWS_ACCESS_KEY_ID")
        assert hit.file == str(f)
        assert hit.line == 1


# ─────────────────────────────────────────────────────────────────────────────
# Pattern registry completeness
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistry:
    REQUIRED_PATTERN_IDS = [
        "aws_access_key_id",
        "aws_secret_access_key",
        "github_pat_classic",
        "github_oauth_token",
        "github_fine_grained_pat",
        "google_api_key",
        "slack_bot_token",
        "stripe_secret_key",
        "jwt_token",
        "openai_api_key",
        "anthropic_api_key",
        "pem_private_key",
        "generic_api_key_assignment",
        "generic_secret_assignment",
        "generic_password_assignment",
    ]

    def test_all_required_patterns_registered(self):
        from secrettriage.detectors.patterns import PATTERN_REGISTRY
        for pid in self.REQUIRED_PATTERN_IDS:
            assert pid in PATTERN_REGISTRY, f"Missing pattern: {pid}"

    def test_every_pattern_has_compiled_regex(self):
        from secrettriage.detectors.patterns import PATTERN_REGISTRY
        import re
        for pid, pat in PATTERN_REGISTRY.items():
            assert isinstance(pat.pattern, re.Pattern), f"{pid} pattern not compiled"

    def test_every_pattern_has_base_severity(self):
        from secrettriage.detectors.patterns import PATTERN_REGISTRY
        valid = {"Critical", "High", "Medium", "Low"}
        for pid, pat in PATTERN_REGISTRY.items():
            assert pat.base_severity in valid, f"{pid} has invalid severity: {pat.base_severity}"
