"""
Responsible-Disclosure Draft Generator (Stage 4).

Generates a per-finding Coordinated Vulnerability Disclosure (CVD) report:
  - Affected asset & finding identification
  - Masked evidence (strict zero-leak offline disclosure)
  - Threat & business impact assessment
  - Clear remediation protocol (rotation, revocation, git scrubbing)
  - Responsible disclosure timeline placeholders
  - Safe harbor / non-exploitation ethical statement
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from secrettriage.detectors.models import Finding


def generate_disclosure_draft(
    finding: "Finding",
    recipient_org: str = "[Organization Name / Security Team]",
    reporter_name: str = "SecretTriage Security Research",
    output_path: Optional[str | Path] = None,
) -> str:
    """
    Generate a coordinated responsible-disclosure notification for a single finding.

    Args:
        finding: Scored Finding object.
        recipient_org: Target organization or security contact.
        reporter_name: Name of researcher or triage team.
        output_path: Optional path to write markdown draft to.

    Returns:
        Markdown disclosure draft string.
    """
    now = datetime.now(timezone.utc)
    discovery_date = now.strftime("%Y-%m-%d")
    ack_date = (now + timedelta(days=3)).strftime("%Y-%m-%d")
    fix_date = (now + timedelta(days=7)).strftime("%Y-%m-%d")
    embargo_date = (now + timedelta(days=90)).strftime("%Y-%m-%d")

    severity = finding.severity or "Medium"
    score = finding.severity_score or 5.0
    impact_summary = finding.severity_reasoning or "Potential unauthorized credential usage"

    # Format context lines with masking
    context_lines = []
    if finding.context_before:
        for line in finding.context_before:
            context_lines.append(f"  {line}")
    context_lines.append(f"> {finding.line}: [EXPOSED SECRET: {finding.masked_value}]")
    if finding.context_after:
        for line in finding.context_after:
            context_lines.append(f"  {line}")
    context_block = "\n".join(context_lines) if context_lines else f"{finding.file}:{finding.line}"

    draft = f"""# Vulnerability Disclosure Report: Exposed {finding.secret_type}

**To**: {recipient_org}  
**From**: {reporter_name}  
**Date**: {discovery_date}  
**Severity**: **{severity.upper()}** (Triage Score: {score:.1f}/10.0)  
**Vulnerability Type**: Sensitive Credential Exposure (CWE-798: Use of Hard-coded Credentials)  

---

## 1. Summary

A security analysis has identified an exposed credential of type **`{finding.secret_type}`** within your repository or public assets. 

This exposure allows unauthorized actors to bypass perimeter controls and access internal resources corresponding to this credential's privileges.

- **Affected Asset / File**: `{finding.file}`
- **Line Number**: `{finding.line}`
- **Credential Type**: `{finding.secret_type}` (Detector: `{finding.detector_name or finding.pattern_id}`)
- **Classifier Assessment**: `{finding.label or 'UNCLASSIFIED'}` (Confidence: {finding.label_confidence:.2f})

---

## 2. Masked Evidence

In compliance with responsible disclosure ethics, the secret has been strictly masked:

```text
{context_block}
```
*Masked Value*: `{finding.masked_value}`  
*(The complete unmasked token is preserved in secure memory if validation by authorized security staff is needed).*

---

## 3. Potential Security Impact

{impact_summary}

Depending on the scopes granted to this credential, exploitation could result in unauthorized administrative access, internal communication eavesdropping, or sensitive customer data exposure.

---

## 4. Remediation Checklist

Please execute the following steps in sequence:

1. **Immediate Revocation**:
   - Invalidate the compromised token `{finding.masked_value}` directly at the provider console or API.
   - Kill active sessions or OAuth tokens spawned under this identity.

2. **Credential Rotation**:
   - Generate a replacement credential with the principle of least privilege.
   - Inject the new credential using an environment variable or secrets manager (e.g., AWS Secrets Manager, Vault).

3. **Access Audit**:
   - Query provider audit logs (e.g. AWS CloudTrail, GitHub Audit Log, Stripe Event Log) for unauthorized API operations originating from unfamiliar IP addresses.

4. **Git History Scrubbing**:
   - **Important**: Deleting the credential in a new commit does **not** remove it from git history.
   - Use `git-filter-repo` or `bfg --delete-files` to purge the commit history across all branches and tags, followed by a force push.

---

## 5. Disclosure Timeline & Embargo

In accordance with industry Coordinated Vulnerability Disclosure (CVD) standards:

- **Initial Notification**: `{discovery_date}`
- **Acknowledgment Requested By**: `{ack_date}` (3 business days)
- **Remediation SLA**: `{fix_date}` (7 calendar days)
- **Public Disclosure Embargo Date**: `{embargo_date}` (90 calendar days)

---

## 6. Safe Harbor & Non-Exploitation Declaration

This report was prepared in good faith. **SecretTriage performs only offline, passive pattern analysis.** At no point were these credentials transmitted over external networks, used to authenticate against third-party endpoints, or utilized to exfiltrate private data.

Please confirm receipt of this disclosure notice and provide a primary security engineering point of contact.
"""

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(draft, encoding="utf-8")

    return draft
