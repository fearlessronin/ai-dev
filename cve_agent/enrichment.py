from __future__ import annotations

from .models import AnalysisResult


def apply_enrichment(
    analysis: AnalysisResult,
    kev_entry: dict | None,
    epss_entry: dict | None,
) -> AnalysisResult:
    if kev_entry:
        analysis.kev_status = True
        analysis.kev_date_added = str(kev_entry.get("dateAdded", "")) or None
        analysis.kev_due_date = str(kev_entry.get("dueDate", "")) or None
        analysis.kev_required_action = str(kev_entry.get("requiredAction", "")) or None

    if epss_entry:
        analysis.epss_score = float(epss_entry.get("epss_score", 0.0))
        analysis.epss_percentile = float(epss_entry.get("epss_percentile", 0.0))

    _assign_priority(analysis)
    return analysis


def _assign_priority(analysis: AnalysisResult) -> None:
    # 0.0 - 1.5 range before capping, weighted for AI relevance + exploitability + exploitation evidence.
    score = 0.0
    reasons: list[str] = []

    ai_component = min(0.5, analysis.confidence * 0.5)
    score += ai_component
    reasons.append(f"AI relevance={analysis.confidence:.2f}")

    if analysis.epss_score is not None:
        epss_component = min(0.35, analysis.epss_score * 0.35)
        score += epss_component
        reasons.append(f"EPSS={analysis.epss_score:.3f}")

    if analysis.kev_status:
        score += 0.25
        reasons.append("KEV listed")

    if analysis.cve.cvss_v31_base is not None:
        cvss_component = min(0.15, (analysis.cve.cvss_v31_base / 10.0) * 0.15)
        score += cvss_component
        reasons.append(f"CVSS={analysis.cve.cvss_v31_base:.1f}")

    analysis.priority_score = round(min(1.0, score), 2)
    analysis.priority_reason = "; ".join(reasons)
