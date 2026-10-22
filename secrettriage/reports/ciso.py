"""
CISO Executive Summary Report Generator (Stage 4).

Generates a concise, one-page executive summary formatted for CISOs and security leadership:
  - Executive overview and threat posture
  - Severity breakdown table (Critical, High, Medium, Low)
  - Top 3 risks described in business-impact language
  - Prioritized strategic and tactical recommended actions
  - False-positive / placeholder triage audit note
  - Markdown and self-contained styled HTML outputs
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from secrettriage.detectors.models import Finding


def _format_markdown_report(findings: list["Finding"], generated_at: str) -> str:
    """Format CISO report as Markdown."""
    total = len(findings)
    severity_counts = Counter(f.severity or "Unknown" for f in findings)
    label_counts = Counter(f.label or "Unclassified" for f in findings)

    crit_count = severity_counts.get("Critical", 0)
    high_count = severity_counts.get("High", 0)
    med_count = severity_counts.get("Medium", 0)
    low_count = severity_counts.get("Low", 0)

    # Determine executive posture
    if crit_count > 0:
        posture = "ELEVATED (CRITICAL SECRETS EXPOSED)"
        posture_desc = "Immediate incident response required. Credentials capable of infrastructure or financial takeover are exposed."
    elif high_count > 0:
        posture = "HIGH ATTENTION REQUIRED"
        posture_desc = "Action required within 24 hours. Sensitive API keys or authentication tokens are exposed."
    elif med_count > 0:
        posture = "MODERATE"
        posture_desc = "Remediate within standard sprint cycle. Internal secrets or scoped tokens identified."
    elif total > 0:
        posture = "LOW RISK"
        posture_desc = "Identified findings consist of public keys or confirmed placeholder examples."
    else:
        posture = "SECURE / CLEAN"
        posture_desc = "No exposed credentials detected in scanned scope."

    # Top 3 risks by severity score (prioritizing LIKELY_REAL and high scores)
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            1 if f.label == "LIKELY_REAL" else 0,
            f.severity_score or 0.0,
        ),
        reverse=True,
    )

    top_risks = [f for f in sorted_findings if (f.severity_score or 0.0) >= 4.0][:3]
    if not top_risks and sorted_findings:
        top_risks = sorted_findings[:3]

    top_risks_md = []
    if top_risks:
        for idx, f in enumerate(top_risks, 1):
            file_loc = f"{f.file}:{f.line}"
            status = f.label or "UNCLASSIFIED"
            score = f.severity_score or 0.0
            top_risks_md.append(
                f"### {idx}. {f.secret_type} — {f.severity} ({score:.1f}/10.0)\n"
                f"- **Location**: `{file_loc}`\n"
                f"- **Status**: `{status}` (Confidence: {f.label_confidence:.2f})\n"
                f"- **Business Impact**: {f.severity_reasoning.split(' | ')[0] if f.severity_reasoning else 'Unspecified credential compromise'}\n"
                f"- **Triage Assessment**: {f.severity_reasoning}\n"
            )
    else:
        top_risks_md.append("> *No high or critical risks identified in the scanned scope.*\n")

    # Placeholder audit breakdown
    placeholders = [f for f in findings if f.label == "LIKELY_PLACEHOLDER"]
    placeholder_note = (
        f"The triage engine analyzed **{total}** total detector hits and filtered/demoted "
        f"**{len(placeholders)}** confirmed placeholder/dummy credentials (e.g. documentation examples, "
        f"test fixtures, repetitive test patterns). Demoting placeholders avoided **{len(placeholders)} false alarms** "
        f"for engineering and security operations."
    )

    md = f"""# SecretTriage — CISO Executive Summary

> **Report Date**: {generated_at}  
> **Overall Security Posture**: **{posture}**  
> *{posture_desc}*

---

## 1. Executive Metrics

| Severity Tier | Count | Triage Status Breakdown | Recommended SLA |
|---|---|---|---|
| **Critical** | **{crit_count}** | {sum(1 for f in findings if f.severity == 'Critical' and f.label == 'LIKELY_REAL')} Real / {sum(1 for f in findings if f.severity == 'Critical' and f.label != 'LIKELY_REAL')} Other | Immediate (0–4 Hours) |
| **High** | **{high_count}** | {sum(1 for f in findings if f.severity == 'High' and f.label == 'LIKELY_REAL')} Real / {sum(1 for f in findings if f.severity == 'High' and f.label != 'LIKELY_REAL')} Other | 24 Hours |
| **Medium** | **{med_count}** | {sum(1 for f in findings if f.severity == 'Medium' and f.label == 'LIKELY_REAL')} Real / {sum(1 for f in findings if f.severity == 'Medium' and f.label != 'LIKELY_REAL')} Other | 7 Days |
| **Low / Info** | **{low_count}** | {sum(1 for f in findings if f.severity == 'Low' and f.label == 'LIKELY_REAL')} Real / {sum(1 for f in findings if f.severity == 'Low' and f.label != 'LIKELY_REAL')} Other | Next Sprint |
| **Total Findings** | **{total}** | **{label_counts.get('LIKELY_REAL', 0)} LIKELY_REAL** / **{label_counts.get('LIKELY_PLACEHOLDER', 0)} PLACEHOLDER** / **{label_counts.get('UNCERTAIN', 0)} UNCERTAIN** | — |

---

## 2. Top Business-Impact Risks

{''.join(top_risks_md)}
---

## 3. Recommended Remediation Plan

1. **Immediate Revocation (Emergency SLA: 0–4h)**:
   - For all **Critical** findings, immediately revoke credentials at the identity provider (AWS IAM, Stripe Dashboard, Cloud Console).
   - Invalidate active sessions and review access logs for abnormal IP addresses or unauthorized API calls since estimated exposure date.

2. **Repository & Build Scrubbing (SLA: 24–48h)**:
   - Scrub secrets from git commit history using `git-filter-repo` or BFG Repo-Cleaner. *Note: Committing a replacement file does NOT purge exposed secrets from commit history.*
   - Invalidate any downstream artifacts (Docker images, CI build caches) compiled with exposed credentials.

3. **Preventative Controls & Hardening (Strategic)**:
   - Deploy automated pre-commit secret detection hooks to prevent local staging of API keys.
   - Enforce centralized secret management (e.g. AWS Secrets Manager, HashiCorp Vault) and eliminate hardcoded `.env` files.

---

## 4. False-Positive & Noise-Reduction Audit

{placeholder_note}

---
*Generated by SecretTriage — Threat Intelligence & Leaked Secret Triage Engine (Offline Validation Only)*
"""
    return md


def _convert_markdown_to_html(md_content: str, title: str = "SecretTriage CISO Executive Report") -> str:
    """Convert Markdown report to a beautifully styled executive HTML document."""
    import html

    # Clean executive CSS styling
    css = """
    <style>
      :root {
        --primary: #0f172a;
        --secondary: #334155;
        --accent: #2563eb;
        --critical: #dc2626;
        --high: #ea580c;
        --medium: #d97706;
        --low: #16a34a;
        --bg: #ffffff;
        --surface: #f8fafc;
        --border: #e2e8f0;
      }
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.6;
        color: var(--primary);
        background: var(--bg);
        margin: 0;
        padding: 40px;
        max-width: 960px;
        margin: 0 auto;
      }
      h1 { font-size: 26px; border-bottom: 2px solid var(--border); padding-bottom: 12px; margin-top: 0; }
      h2 { font-size: 20px; color: var(--secondary); margin-top: 32px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
      h3 { font-size: 16px; margin-top: 20px; color: var(--primary); }
      blockquote {
        background: var(--surface);
        border-left: 4px solid var(--accent);
        margin: 16px 0;
        padding: 12px 16px;
        color: var(--secondary);
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        font-size: 14px;
      }
      th, td {
        border: 1px solid var(--border);
        padding: 10px 14px;
        text-align: left;
      }
      th {
        background-color: var(--surface);
        font-weight: 600;
      }
      code {
        background: var(--surface);
        border: 1px solid var(--border);
        padding: 2px 6px;
        border-radius: 4px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
      }
      hr { border: 0; height: 1px; background: var(--border); margin: 30px 0; }
      .footer { font-size: 12px; color: var(--secondary); margin-top: 40px; text-align: center; }
      @media print {
        body { padding: 0; }
        .no-print { display: none; }
      }
    </style>
    """

    # Minimal robust parser for the executive report structure
    lines = md_content.splitlines()
    html_lines: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"  <title>{html.escape(title)}</title>",
        css,
        "</head>",
        "<body>",
    ]

    in_table = False
    in_blockquote = False

    for line in lines:
        s = line.strip()
        if not s:
            if in_blockquote:
                html_lines.append("</blockquote>")
                in_blockquote = False
            continue

        if s.startswith("# "):
            html_lines.append(f"<h1>{html.escape(s[2:])}</h1>")
        elif s.startswith("## "):
            html_lines.append(f"<h2>{html.escape(s[3:])}</h2>")
        elif s.startswith("### "):
            html_lines.append(f"<h3>{html.escape(s[4:])}</h3>")
        elif s.startswith("> "):
            if not in_blockquote:
                html_lines.append("<blockquote>")
                in_blockquote = True
            html_lines.append(f"<p>{html.escape(s[2:])}</p>")
        elif s.startswith("---"):
            if in_blockquote:
                html_lines.append("</blockquote>")
                in_blockquote = False
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append("<hr>")
        elif s.startswith("|") and s.endswith("|"):
            parts = [p.strip() for p in s[1:-1].split("|")]
            if all(set(p).issubset({"-", ":", " "}) for p in parts):
                continue  # Header divider
            if not in_table:
                in_table = True
                html_lines.append("<table>")
                html_lines.append("<tr>" + "".join(f"<th>{html.escape(p)}</th>" for p in parts) + "</tr>")
            else:
                html_lines.append("<tr>" + "".join(f"<td>{html.escape(p)}</td>" for p in parts) + "</tr>")
        elif s.startswith("- "):
            html_lines.append(f"<li>{html.escape(s[2:])}</li>")
        elif s.startswith("1. ") or s.startswith("2. ") or s.startswith("3. "):
            html_lines.append(f"<p><strong>{html.escape(s[:3])}</strong> {html.escape(s[3:])}</p>")
        else:
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append(f"<p>{html.escape(s)}</p>")

    if in_blockquote:
        html_lines.append("</blockquote>")
    if in_table:
        html_lines.append("</table>")

    html_lines.append("</body></html>")
    return "\n".join(html_lines)


def generate_ciso_report(
    findings: list["Finding"],
    output_path: Optional[str | Path] = None,
    to_html: bool = False,
) -> str:
    """
    Generate an executive CISO report.

    Args:
        findings: List of Finding objects (already scanned, classified, scored).
        output_path: Optional file path to write the report to.
        to_html: If True, returns HTML string instead of Markdown.

    Returns:
        Report string (Markdown or HTML).
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md_content = _format_markdown_report(findings, generated_at)

    result = _convert_markdown_to_html(md_content) if to_html else md_content

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        # If output_path ends with .html, write HTML regardless
        if out_file.suffix.lower() == ".html" and not to_html:
            write_content = _convert_markdown_to_html(md_content)
        else:
            write_content = result
        out_file.write_text(write_content, encoding="utf-8")

    return result
