"""
Gap analyser: computes which controls are addressed, partial, or missing,
assigns risk scores, and assembles the AuditResult.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from src.frameworks.loader import Control, Framework
from src.mapper.control_mapper import ControlMatch

logger = logging.getLogger(__name__)

CoverageStatus = Literal["ADDRESSED", "PARTIAL", "MISSING"]

# Thresholds for coverage classification
THRESHOLD_ADDRESSED = 0.35
THRESHOLD_PARTIAL = 0.10

# Risk score weights per severity
SEVERITY_WEIGHT = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


@dataclass
class ControlResult:
    control: Control
    status: CoverageStatus
    score: float
    matched_keywords: list[str]
    evidence_snippets: list[str]
    risk_contribution: int  # weighted risk points


@dataclass
class CategoryResult:
    category_id: str
    category_name: str
    total_controls: int
    addressed: int
    partial: int
    missing: int
    coverage_pct: float
    controls: list[ControlResult] = field(default_factory=list)


@dataclass
class AuditResult:
    framework_id: str
    framework_name: str
    framework_version: str
    document_source: str
    document_sha256: str
    audited_at: str

    total_controls: int
    addressed_count: int
    partial_count: int
    missing_count: int
    overall_coverage_pct: float

    risk_score: int          # 0–100 composite risk (higher = riskier)
    risk_label: str          # LOW / MEDIUM / HIGH / CRITICAL

    categories: list[CategoryResult] = field(default_factory=list)
    pii_redactions: int = 0
    warnings: list[str] = field(default_factory=list)

    # Filled by LLM enrichment step
    executive_summary: str = ""
    gap_narratives: dict[str, str] = field(default_factory=dict)
    remediation_guidance: dict[str, str] = field(default_factory=dict)


def analyse(
    matches: list[ControlMatch],
    framework: Framework,
    document_source: str = "",
    document_sha256: str = "",
    pii_redactions: int = 0,
    warnings: list[str] | None = None,
) -> AuditResult:
    """
    Convert a list of ControlMatches into a structured AuditResult.

    Args:
        matches: Output from map_document().
        framework: The Framework that was audited.
        document_source: Label or path of the source document.
        document_sha256: Integrity hash of the ingested document.
        pii_redactions: Number of PII patterns redacted during ingest.
        warnings: Any warnings accumulated upstream.

    Returns:
        AuditResult ready for LLM enrichment and report generation.
    """
    match_by_id = {m.control.id: m for m in matches}

    addressed = partial = missing = 0
    total_risk_possible = 0
    total_risk_actual = 0  # risk accumulated from gaps

    cat_results: list[CategoryResult] = []

    for category in framework.categories:
        ctrl_results: list[ControlResult] = []
        cat_addressed = cat_partial = cat_missing = 0

        for control in category.controls:
            weight = SEVERITY_WEIGHT.get(control.severity, 1)
            total_risk_possible += weight

            match = match_by_id.get(control.id)
            score = match.score if match else 0.0

            if score >= THRESHOLD_ADDRESSED:
                status: CoverageStatus = "ADDRESSED"
                cat_addressed += 1
                addressed += 1
                risk_contrib = 0
            elif score >= THRESHOLD_PARTIAL:
                status = "PARTIAL"
                cat_partial += 1
                partial += 1
                # Partial coverage = half the risk
                risk_contrib = weight
                total_risk_actual += weight
            else:
                status = "MISSING"
                cat_missing += 1
                missing += 1
                risk_contrib = weight * 2
                total_risk_actual += weight * 2

            ctrl_results.append(
                ControlResult(
                    control=control,
                    status=status,
                    score=score,
                    matched_keywords=match.matched_keywords if match else [],
                    evidence_snippets=match.evidence_snippets if match else [],
                    risk_contribution=risk_contrib,
                )
            )

        total_in_cat = len(category.controls)
        coverage_pct = (
            round(cat_addressed / total_in_cat * 100, 1) if total_in_cat else 0.0
        )

        cat_results.append(
            CategoryResult(
                category_id=category.id,
                category_name=category.name,
                total_controls=total_in_cat,
                addressed=cat_addressed,
                partial=cat_partial,
                missing=cat_missing,
                coverage_pct=coverage_pct,
                controls=ctrl_results,
            )
        )

    total_controls = addressed + partial + missing
    overall_pct = round(addressed / total_controls * 100, 1) if total_controls else 0.0

    # Normalise risk score to 0–100
    max_possible_risk = total_risk_possible * 2  # worst case: everything missing HIGH
    risk_score = (
        round(min(total_risk_actual / max_possible_risk * 100, 100))
        if max_possible_risk
        else 0
    )
    risk_label = _risk_label(risk_score)

    logger.info(
        "Analysis complete — %d/%d addressed, risk=%d (%s)",
        addressed,
        total_controls,
        risk_score,
        risk_label,
    )

    return AuditResult(
        framework_id=framework.id,
        framework_name=framework.name,
        framework_version=framework.version,
        document_source=document_source,
        document_sha256=document_sha256,
        audited_at=datetime.now(timezone.utc).isoformat(),
        total_controls=total_controls,
        addressed_count=addressed,
        partial_count=partial,
        missing_count=missing,
        overall_coverage_pct=overall_pct,
        risk_score=risk_score,
        risk_label=risk_label,
        categories=cat_results,
        pii_redactions=pii_redactions,
        warnings=warnings or [],
    )


def _risk_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
