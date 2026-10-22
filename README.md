# SecretTriage

> **Leaked-secret triage engine** — portfolio project for a Security Consultant Intern role.

SecretTriage scans text, files, and repositories for exposed credentials, classifies each
hit as a real-format secret or a placeholder, scores severity, and generates a CISO-ready
summary plus a responsible-disclosure draft — **entirely offline**.

---

## ⚠️ Ethics & Synthetic Data Disclaimer

**All secret values in test fixtures, the synthetic corpus, and this README are
100% synthetic.** They are generated to match the *format* of real credentials
(length, prefix, character class) but are never valid credentials and cannot
authenticate to any service.

**SecretTriage never authenticates to or calls any third-party service with a
found secret. All validation is offline: format, checksum, entropy, and context.**

---

## Architecture

```mermaid
flowchart TD
    A[Input: text / file / repo] --> B[Detectors\nRegex + Pattern Registry]
    B --> C[Finding objects\nmasked output, full value in memory]
    C --> D[Classifier\nentropy · context · format · checksum]
    D --> E[Scorer\ntype · location · confidence · blast radius]
    E --> F[Reports]
    F --> G[CISO Summary\nmarkdown → HTML/PDF]
    F --> H[Disclosure Draft\nper-finding markdown]
    C --> I[(SQLite Storage)]
    I --> J[Streamlit Dashboard]
    G --> J
    H --> J
```

---

## Project Layout

```
secrettriage/
├── detectors/          # Pattern registry + scanner (Stage 1)
│   ├── models.py       # Finding dataclass, masking logic
│   ├── patterns.py     # 24 named PatternDef entries
│   └── registry.py     # scan_text(), scan_file()
├── classifier/         # Real-vs-placeholder classifier (Stage 2)
├── scoring/            # Severity scorer (Stage 3)
├── reports/            # CISO report + disclosure draft (Stage 4)
└── storage/            # SQLite persistence (Stage 5)
data/
├── corpus/             # Synthetic labeled corpus (Stage 2)
└── generate_corpus.py  # Corpus generator script
results/
└── eval.md             # Classifier evaluation results (Stage 2)
tests/                  # pytest test suite
app.py                  # Streamlit dashboard (Stage 5)
```

---

## Detectors (Stage 1)

| Pattern ID | Secret Type | Base Severity |
|---|---|---|
| `aws_access_key_id` | AWS_ACCESS_KEY_ID | Critical |
| `aws_secret_access_key` | AWS_SECRET_ACCESS_KEY | Critical |
| `github_pat_classic` | GITHUB_TOKEN | High |
| `github_oauth_token` | GITHUB_TOKEN | High |
| `github_fine_grained_pat` | GITHUB_TOKEN | High |
| `github_server_to_server` | GITHUB_TOKEN | High |
| `github_refresh_token` | GITHUB_TOKEN | Medium |
| `google_api_key` | GOOGLE_API_KEY | High |
| `slack_bot_token` | SLACK_TOKEN | High |
| `slack_user_token` | SLACK_TOKEN | High |
| `slack_workspace_token` | SLACK_TOKEN | Medium |
| `slack_webhook_url` | SLACK_WEBHOOK | High |
| `stripe_secret_key` | STRIPE_SECRET_KEY | Critical |
| `stripe_publishable_key` | STRIPE_PUBLISHABLE_KEY | Low |
| `stripe_restricted_key` | STRIPE_RESTRICTED_KEY | Medium |
| `jwt_token` | JWT | Medium |
| `openai_api_key` | OPENAI_API_KEY | High |
| `openai_api_key_v2` | OPENAI_API_KEY | High |
| `anthropic_api_key` | ANTHROPIC_API_KEY | High |
| `pem_private_key` | PRIVATE_KEY | Critical |
| `pkcs8_private_key` | PRIVATE_KEY | Critical |
| `generic_api_key_assignment` | GENERIC_API_KEY | Medium |
| `generic_secret_assignment` | GENERIC_SECRET | Medium |
| `generic_password_assignment` | GENERIC_PASSWORD | Medium |
| `generic_token_assignment` | GENERIC_TOKEN | Medium |

---

## How It Classifies (Stage 2 preview)

Each Finding is evaluated on:

1. **Shannon entropy** — placeholder values are low-entropy (repeated chars, sequences)
2. **Character-class diversity** — real secrets use mixed upper/lower/digit/symbol
3. **Known-example-value list** — AKIAIOSFODNN7EXAMPLE and similar canonical examples
4. **Keyword context** — surrounding words: `example`, `test`, `dummy`, `changeme`, `placeholder`
5. **File-path context** — `tests/`, `docs/`, `README`, `fixtures/` lower confidence
6. **Format/checksum validation** — AWS key prefix rules, GitHub token structure
7. **Repetition/sequential checks** — `aaaa...`, `1234...` patterns

Output: `LIKELY_REAL` / `LIKELY_PLACEHOLDER` / `UNCERTAIN` + 0–1 confidence + human-readable reasons.

---

## Eval Results (Stage 2 — from `python data/evaluate_corpus.py`)

Corpus: **187 samples** (112 LIKELY_REAL, 75 LIKELY_PLACEHOLDER) across 11 secret types.
All values are **synthetic** (seed=42 PRNG). See `data/generate_corpus.py`.

| Metric | Value |
|---|---|
| Precision (REAL) | **100.0%** |
| Recall (REAL) | **100.0%** |
| F1 (REAL) | **100.0%** |
| Accuracy (hard calls only) | **93.0%** |

**Confusion matrix (rows = truth, cols = predicted):**

| | LIKELY_REAL | LIKELY_PLACEHOLDER | UNCERTAIN |
|---|---|---|---|
| LIKELY_REAL | 108 TP | 0 FN | 4 |
| LIKELY_PLACEHOLDER | 0 FP | 66 TN | 9 |

13 findings were classified `UNCERTAIN` (high-entropy values in test paths, or JWTs with ambiguous context).
Zero hard misclassifications. See [`results/eval.md`](file:///e:/Leaked%20Secret%20Triage%20Engine/results/eval.md) for the per-type breakdown.
---

## Severity Scoring (Stage 3)

SecretTriage computes an auditable 0.0–10.0 severity score for every finding, mapping to **Critical**, **High**, **Medium**, or **Low**, governed by configurable weights in [`secrettriage/scoring/weights.json`](file:///e:/Leaked%20Secret%20Triage%20Engine/secrettriage/scoring/weights.json).

### Scoring Dimensions

1. **Secret Type & Blast Radius**:
   - Cloud Root / Infrastructure (`AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, `PRIVATE_KEY`): Base 9.0–9.5 (Critical account takeover & infrastructure compromise).
   - Financial Credentials (`STRIPE_SECRET_KEY`): Base 9.0 (Direct unauthorized transaction capability).
   - CI/CD & Code Access (`GITHUB_TOKEN`): Base 8.0 (Pipeline poisoning & repo compromise).
   - High-Value API Keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`): Base 7.0–7.5 (Billing drain & data exfiltration).
   - Communication Webhooks/Tokens (`SLACK_TOKEN`, `SLACK_WEBHOOK`): Base 6.5–7.0 (Internal espionage & phishing).
   - Client-side / Public Keys (`STRIPE_PUBLISHABLE_KEY`): Base 2.0 (Low risk, public by design).

2. **Exposure Location Risk**:
   - **Client-side JS/Frontend** (`.js`, `.jsx`, `.ts`, `.tsx`, `public/`, `dist/`): `+1.5` severity boost for backend secrets exposed to end-user browsers (no penalty for publishable keys).
   - **Production Config & Environment** (`.env*`, `docker-compose.yml`, `k8s/`, `terraform/`): `+1.0` boost.
   - **CI/CD Pipelines** (`.github/`, `.gitlab-ci.yml`): `+0.8` boost.
   - **Test & Docs** (`tests/`, `fixtures/`, `docs/`, `README`): `-2.0` discount.

3. **Classifier Demotion & Confidence**:
   - **`LIKELY_PLACEHOLDER`**: Automatically demoted (score scaled by `0.2`, capped at `2.5` -> **Low** severity). Even if an AWS secret key pattern is matched, a dummy value never triggers a false critical alarm.
   - **`LIKELY_REAL`**: Scaled by classification confidence (`base_factor 0.85 + 0.15 * confidence`).
   - **`UNCERTAIN`**: Moderately discounted (`0.85x`) to reflect confidence uncertainty while maintaining triage visibility.

| Severity Tier | Score Range | Default Action |
|---|---|---|
| **Critical** | `8.5 – 10.0` | Immediate emergency revocation, incident ticket, credential rotation |
| **High** | `6.5 – 8.4` | Same-day triage, access audit, token re-issuance |
| **Medium** | `4.0 – 6.4` | Scheduled secret remediation, repo scrubbing |
| **Low** | `0.0 – 3.9` | Informational logging or confirmed placeholder |

---

## Limitations

> *To be filled with honest metrics after Stage 2 eval.*

1. **Regex-only detection** misses secrets split across lines or obfuscated with string concatenation.
2. **No semantic understanding** — cannot tell if a value is functionally used vs. merely assigned.
3. **Generic patterns** (`api_key = ...`) have a high false-positive rate for short/low-entropy values.
4. **Context window is narrow** — only ±2 lines; comment blocks further away are missed.
5. **No multi-file correlation** — a key in one file matched against its use in another is not tracked.

---

## Running Tests

```bash
# From project root (no install needed):
python -m pytest tests/ -v
```

## Running the Dashboard

```bash
streamlit run app.py
```

---

## Stage Progress

| Stage | Description | Status |
|---|---|---|
| 1 | Scaffold + Detectors (24 patterns across 11 secret types) | ✅ Complete (39 tests pass) |
| 2 | Labeled Corpus + Classifier (187 samples, 100% precision/recall) | ✅ Complete (64 tests pass) |
| 3 | Severity Scoring (multi-factor weights, blast radius, location modifiers) | ✅ Complete (16 tests pass) |
| 4 | CISO Executive Report + Responsible-Disclosure Draft | ✅ Complete (7 tests pass) |
| 5 | SQLite Storage Persistence + Streamlit Analytics Dashboard | ✅ Complete (6 tests pass) |
| 6 | Full Test Suite (132/132 pass, 96% coverage) + Documentation | ✅ Complete |

