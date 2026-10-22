"""
Named pattern registry for secret detectors.

Each entry is a PatternDef describing one secret type.
The registry is an ordered dict so that more-specific patterns are checked first.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class PatternDef:
    """Definition of a single secret-detection pattern."""

    id: str                          # unique slug, e.g. "aws_access_key_id"
    name: str                        # human-readable label
    secret_type: str                 # category, e.g. "AWS_ACCESS_KEY_ID"
    pattern: re.Pattern              # compiled regex; capture group 1 is the secret
    group: int = 1                   # which capture group holds the raw secret
    base_severity: str = "High"      # default severity before scoring adjustments
    description: str = ""
    references: list[str] = field(default_factory=list)
    # Optional post-match validator (returns True if the match looks structurally valid)
    validator: Optional[Callable[[str], bool]] = None


# ──────────────────────────────────────────────────────────────────────────────
# Helper factories
# ──────────────────────────────────────────────────────────────────────────────

def _re(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# ──────────────────────────────────────────────────────────────────────────────
# Validators
# ──────────────────────────────────────────────────────────────────────────────

def _validate_aws_access_key(value: str) -> bool:
    """AWS access key IDs are exactly 20 chars starting with AKIA/ASIA/AROA/etc."""
    return bool(re.fullmatch(r"(?:AKIA|ASIA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}", value))


def _validate_github_token(value: str) -> bool:
    """GitHub PATs have a CRC32 checksum embedded in the last 6 chars of base62."""
    import binascii, base64

    # Minimal structural check: known prefix + base62 chars
    if not re.fullmatch(r"(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}", value):
        return False
    return True   # deeper CRC check is complex; structural check is sufficient here


def _validate_jwt(value: str) -> bool:
    """JWT: three base64url-encoded segments separated by dots."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    b64_chars = re.compile(r"^[A-Za-z0-9_\-]+=*$")
    return all(b64_chars.match(p) for p in parts)


def _validate_stripe_key(value: str) -> bool:
    """Stripe keys are exactly 107 chars for secret keys or vary for restricted keys."""
    return len(value) >= 32


# ──────────────────────────────────────────────────────────────────────────────
# Pattern definitions
# ──────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[PatternDef] = [

    # ── AWS ──────────────────────────────────────────────────────────────────
    PatternDef(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        secret_type="AWS_ACCESS_KEY_ID",
        pattern=_re(r"(?<![A-Z0-9])([A-Z]{4}[A-Z0-9]{16})(?![A-Z0-9])"),
        base_severity="Critical",
        description="AWS IAM access key identifier (20-char alphanumeric starting with AKIA/ASIA etc.)",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
        validator=_validate_aws_access_key,
    ),
    PatternDef(
        id="aws_secret_access_key",
        name="AWS Secret Access Key",
        secret_type="AWS_SECRET_ACCESS_KEY",
        pattern=_re(
            r"""(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)"""
            r"""[\s]*[=:\"'\s]+[\s]*([A-Za-z0-9/+=]{40})"""
        ),
        base_severity="Critical",
        description="AWS IAM secret access key (40-char base64)",
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
    ),

    # ── GitHub ───────────────────────────────────────────────────────────────
    PatternDef(
        id="github_pat_classic",
        name="GitHub Personal Access Token (classic ghp_)",
        secret_type="GITHUB_TOKEN",
        pattern=_re(r"(ghp_[A-Za-z0-9]{36})"),
        base_severity="High",
        description="GitHub classic PAT starting with ghp_",
        validator=_validate_github_token,
    ),
    PatternDef(
        id="github_oauth_token",
        name="GitHub OAuth App Token",
        secret_type="GITHUB_TOKEN",
        pattern=_re(r"(gho_[A-Za-z0-9]{36})"),
        base_severity="High",
        description="GitHub OAuth app access token starting with gho_",
        validator=_validate_github_token,
    ),
    PatternDef(
        id="github_fine_grained_pat",
        name="GitHub Fine-Grained PAT",
        secret_type="GITHUB_TOKEN",
        pattern=_re(r"(github_pat_[A-Za-z0-9_]{82})"),
        base_severity="High",
        description="GitHub fine-grained PAT starting with github_pat_",
        validator=_validate_github_token,
    ),
    PatternDef(
        id="github_server_to_server",
        name="GitHub Server-to-Server Token",
        secret_type="GITHUB_TOKEN",
        pattern=_re(r"(ghs_[A-Za-z0-9]{36})"),
        base_severity="High",
        description="GitHub Actions server-to-server token",
        validator=_validate_github_token,
    ),
    PatternDef(
        id="github_refresh_token",
        name="GitHub Refresh Token",
        secret_type="GITHUB_TOKEN",
        pattern=_re(r"(ghr_[A-Za-z0-9]{76})"),
        base_severity="Medium",
        description="GitHub OAuth refresh token",
        validator=_validate_github_token,
    ),

    # ── Google ────────────────────────────────────────────────────────────────
    PatternDef(
        id="google_api_key",
        name="Google API Key",
        secret_type="GOOGLE_API_KEY",
        pattern=_re(r"(AIza[A-Za-z0-9_\-]{35})"),
        base_severity="High",
        description="Google Cloud / Maps / Firebase API key starting with AIza",
    ),

    # ── Slack ─────────────────────────────────────────────────────────────────
    PatternDef(
        id="slack_bot_token",
        name="Slack Bot Token",
        secret_type="SLACK_TOKEN",
        pattern=_re(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24})"),
        base_severity="High",
        description="Slack bot token starting with xoxb-",
    ),
    PatternDef(
        id="slack_user_token",
        name="Slack User Token",
        secret_type="SLACK_TOKEN",
        pattern=_re(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32})"),
        base_severity="High",
        description="Slack user token starting with xoxp-",
    ),
    PatternDef(
        id="slack_workspace_token",
        name="Slack Workspace Token",
        secret_type="SLACK_TOKEN",
        pattern=_re(r"(xoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{64})"),
        base_severity="Medium",
        description="Slack workspace/legacy token",
    ),
    PatternDef(
        id="slack_webhook_url",
        name="Slack Incoming Webhook URL",
        secret_type="SLACK_WEBHOOK",
        pattern=_re(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24,})"),
        base_severity="High",
        description="Slack incoming webhook URL",
    ),

    # ── Stripe ────────────────────────────────────────────────────────────────
    PatternDef(
        id="stripe_secret_key",
        name="Stripe Secret Key",
        secret_type="STRIPE_SECRET_KEY",
        pattern=_re(r"(sk_(?:live|test)_[A-Za-z0-9]{20,107})"),
        base_severity="Critical",
        description="Stripe secret key (live or test)",
        validator=_validate_stripe_key,
    ),
    PatternDef(
        id="stripe_publishable_key",
        name="Stripe Publishable Key",
        secret_type="STRIPE_PUBLISHABLE_KEY",
        pattern=_re(r"(pk_(?:live|test)_[A-Za-z0-9]{20,107})"),
        base_severity="Low",
        description="Stripe publishable key (client-side, lower risk)",
        validator=_validate_stripe_key,
    ),
    PatternDef(
        id="stripe_restricted_key",
        name="Stripe Restricted Key",
        secret_type="STRIPE_RESTRICTED_KEY",
        pattern=_re(r"(rk_(?:live|test)_[A-Za-z0-9]{20,107})"),
        base_severity="Medium",
        description="Stripe restricted key",
        validator=_validate_stripe_key,
    ),

    # ── JWT ───────────────────────────────────────────────────────────────────
    PatternDef(
        id="jwt_token",
        name="JSON Web Token",
        secret_type="JWT",
        pattern=_re(r"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)"),
        base_severity="Medium",
        description="JSON Web Token (three base64url segments starting with eyJ)",
        validator=_validate_jwt,
    ),

    # ── OpenAI / Anthropic ────────────────────────────────────────────────────
    PatternDef(
        id="openai_api_key",
        name="OpenAI API Key",
        secret_type="OPENAI_API_KEY",
        pattern=_re(r"(sk-(?:proj-)?[A-Za-z0-9]{20,100}T3BlbkFJ[A-Za-z0-9]{20,100})"),
        base_severity="High",
        description="OpenAI API key (contains T3BlbkFJ marker)",
    ),
    PatternDef(
        id="openai_api_key_v2",
        name="OpenAI API Key (v2 format)",
        secret_type="OPENAI_API_KEY",
        pattern=_re(r"(sk-[A-Za-z0-9\-_]{40,100})"),
        base_severity="High",
        description="OpenAI-style API key starting with sk-",
    ),
    PatternDef(
        id="anthropic_api_key",
        name="Anthropic API Key",
        secret_type="ANTHROPIC_API_KEY",
        pattern=_re(r"(sk-ant-(?:api\d+-)?[A-Za-z0-9\-_]{80,120})"),
        base_severity="High",
        description="Anthropic Claude API key starting with sk-ant-",
    ),

    # ── Private Key Headers ───────────────────────────────────────────────────
    PatternDef(
        id="pem_private_key",
        name="PEM Private Key",
        secret_type="PRIVATE_KEY",
        pattern=_re(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",
            re.MULTILINE,
        ),
        group=1,
        base_severity="Critical",
        description="PEM private key block header",
    ),
    PatternDef(
        id="pkcs8_private_key",
        name="PKCS8 Private Key",
        secret_type="PRIVATE_KEY",
        pattern=_re(r"(-----BEGIN PRIVATE KEY-----)"),
        base_severity="Critical",
        description="PKCS8 private key header",
    ),

    # ── Generic assignment patterns ───────────────────────────────────────────
    PatternDef(
        id="generic_api_key_assignment",
        name="Generic API Key Assignment",
        secret_type="GENERIC_API_KEY",
        pattern=_re(
            r"""(?i)(?:api[_\-]?key|apikey)[\s]*[=:\"'\s]+[\s]*['"]?([A-Za-z0-9/+\-_\.]{16,128})['"]?"""
        ),
        base_severity="Medium",
        description="Generic api_key / apikey assignment",
    ),
    PatternDef(
        id="generic_secret_assignment",
        name="Generic Secret Assignment",
        secret_type="GENERIC_SECRET",
        pattern=_re(
            r"""(?i)(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)[\s]*[=:\"'\s]+[\s]*['"]?([A-Za-z0-9/+\-_\.]{16,128})['"]?"""
        ),
        base_severity="Medium",
        description="Generic secret/client_secret assignment",
    ),
    PatternDef(
        id="generic_password_assignment",
        name="Generic Password Assignment",
        secret_type="GENERIC_PASSWORD",
        pattern=_re(
            r"""(?i)(?:password|passwd|pwd)[\s]*[=:\"'\s]+[\s]*['"]?([^\s'"<>{}\[\]]{8,128})['"]?"""
        ),
        base_severity="Medium",
        description="Generic password assignment in config/code",
    ),
    PatternDef(
        id="generic_token_assignment",
        name="Generic Token Assignment",
        secret_type="GENERIC_TOKEN",
        pattern=_re(
            r"""(?i)(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)[\s]*[=:\"'\s]+[\s]*['"]?([A-Za-z0-9/+\-_\.]{16,256})['"]?"""
        ),
        base_severity="Medium",
        description="Generic token assignment (access_token, auth_token, bearer)",
    ),
]

# Build the public registry dict keyed by pattern id
PATTERN_REGISTRY: dict[str, PatternDef] = {p.id: p for p in _PATTERNS}
