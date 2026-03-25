"""
Report generators: JSON (machine-readable) and Markdown (human-readable).
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from src.analyser.gap_analyser import AuditResult, CoverageStatus

logger = logging.getLogger(__name__)

# Status emoji for Markdown output
_STATUS_ICON: dict[CoverageStatus, str] = {
    "ADDRESSED": "✅",
    "PARTIAL": "⚠️",
    "MISSING": "❌",
}

_RISK_COLOUR: dict[str, str] = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(result: AuditResult, output_path: str | Path | None = None) -> str:
    """
    Serialise AuditResult to a clean JSON string.

    Args:
        result: Completed AuditResult.
        output_path: If provided, write to this path.

    Returns:
        JSON string.
    """
    data = _result_to_dict(result)
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        _write_file(json_str, output_path)

    return json_str


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_markdown_report(result: AuditResult, output_path: str | Path | None = None) -> str:
    """
    Render AuditResult as a human-readable Markdown report.

    Args:
        result: Completed AuditResult.
        output_path: If provided, write to this path.

    Returns:
        Markdown string.
    """
    lines: list[str] = []

    # --- Header ---
    lines.append(f"# AI Policy Audit Report\n")
    lines.append(f"**Framework:** {result.framework_name} v{result.framework_version}  ")
    lines.append(f"**Document:** `{result.document_source}`  ")
    lines.append(f"**Audited at:** {result.audited_at}  ")
    lines.append(f"**Document SHA-256:** `{result.document_sha256[:16]}...`  \n")

    if result.warnings:
        lines.append("---\n")
        lines.append("**⚠️ Warnings**\n")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    # --- Risk summary ---
    risk_icon = _RISK_COLOUR.get(result.risk_label, "")
    lines.append("---\n")
    lines.append("## Risk Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Overall coverage | **{result.overall_coverage_pct}%** |")
    lines.append(f"| Risk score | **{result.risk_score}/100** |")
    lines.append(f"| Risk label | {risk_icon} **{result.risk_label}** |")
    lines.append(f"| Controls addressed | {result.addressed_count} / {result.total_controls} |")
    lines.append(f"| Controls partial | {result.partial_count} / {result.total_controls} |")
    lines.append(f"| Controls missing | {result.missing_count} / {result.total_controls} |")
    lines.append("")

    # --- Executive summary ---
    if result.executive_summary:
        lines.append("---\n")
        lines.append("## Executive Summary\n")
        lines.append(result.executive_summary)
        lines.append("")

    # --- Category breakdown ---
    lines.append("---\n")
    lines.append("## Control Coverage by Category\n")

    for cat in result.categories:
        lines.append(f"### {cat.category_name}\n")
        lines.append(
            f"Coverage: **{cat.coverage_pct}%** "
            f"({cat.addressed} addressed, {cat.partial} partial, {cat.missing} missing)\n"
        )
        lines.append("| Control | Severity | Status | Score | Keywords matched |")
        lines.append("|---------|----------|--------|-------|-----------------|")
        for ctrl in cat.controls:
            icon = _STATUS_ICON.get(ctrl.status, "?")
            kw_str = ", ".join(ctrl.matched_keywords[:5]) or "—"
            lines.append(
                f"| **{ctrl.control.id}** {ctrl.control.name} "
                f"| {ctrl.control.severity} "
                f"| {icon} {ctrl.status} "
                f"| {ctrl.score:.2f} "
                f"| {kw_str} |"
            )
        lines.append("")

    # --- Gap details ---
    missing_ctrls = [
        ctrl
        for cat in result.categories
        for ctrl in cat.controls
        if ctrl.status in ("MISSING", "PARTIAL")
    ]

    if missing_ctrls:
        lines.append("---\n")
        lines.append("## Gap Details\n")

        for ctrl in missing_ctrls:
            icon = _STATUS_ICON[ctrl.status]
            lines.append(f"### {icon} [{ctrl.control.id}] {ctrl.control.name}\n")
            lines.append(f"**Status:** {ctrl.status}  ")
            lines.append(f"**Severity:** {ctrl.control.severity}  ")
            lines.append(f"**Score:** {ctrl.score:.3f}  \n")
            lines.append(f"**Control description:**  \n{ctrl.control.description}\n")

            if ctrl.evidence_snippets:
                lines.append("**Evidence found:**")
                for snip in ctrl.evidence_snippets:
                    lines.append(f"> {snip}")
                lines.append("")

            narrative = result.gap_narratives.get(ctrl.control.id)
            if narrative:
                lines.append(f"**Why this gap matters:**  \n{narrative}\n")

            remediation = result.remediation_guidance.get(ctrl.control.id)
            if remediation:
                lines.append(f"**Remediation guidance:**  \n{remediation}\n")

            if ctrl.control.article:
                lines.append(f"*Reference: {ctrl.control.article}*\n")

    # --- Footer ---
    lines.append("---")
    lines.append("*Generated by [ai-policy-auditor](https://github.com/your-org/ai-policy-auditor)*")

    md = "\n".join(lines)

    if output_path:
        _write_file(md, output_path)

    return md


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_file(content: str, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    logger.info("Report written to %s", p)


def _result_to_dict(result: AuditResult) -> dict:
    """Convert AuditResult to a JSON-serialisable dict, excluding non-serialisable types."""
    d = asdict(result)

    # Flatten nested dataclasses into plain dicts — asdict already does this,
    # but we clean up the control objects to remove verbose description from JSON.
    for cat in d.get("categories", []):
        for ctrl in cat.get("controls", []):
            # Keep description in JSON but truncate if very long
            if "control" in ctrl:
                desc = ctrl["control"].get("description", "")
                ctrl["control"]["description"] = desc[:300] + ("…" if len(desc) > 300 else "")

    return d
