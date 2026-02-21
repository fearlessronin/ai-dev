from __future__ import annotations

from .models import AnalysisResult


def apply_phase3_correlation(
    analysis: AnalysisResult,
    kev_entry: dict | None,
    epss_entry: dict | None,
    cveorg_entry: dict | None,
    osv_entry: dict | None,
) -> AnalysisResult:
    score = 0.0
    evidence: list[str] = []
    contradictions: list[str] = []

    if kev_entry:
        score += 0.35
        evidence.append("KEV indicates known exploitation")

    epss_score = _safe_float((epss_entry or {}).get("epss_score"))
    if epss_score >= 0.7:
        score += 0.25
        evidence.append(f"EPSS high ({epss_score:.3f})")
    elif epss_score >= 0.3:
        score += 0.15
        evidence.append(f"EPSS elevated ({epss_score:.3f})")
    elif epss_score > 0.0:
        score += 0.05
        evidence.append(f"EPSS present ({epss_score:.3f})")

    cveorg_fixed = _extract_cveorg_fixed_versions(cveorg_entry)
    osv_fixed = _extract_osv_fixed_versions(osv_entry)

    if analysis.has_fix:
        score += 0.1
        evidence.append("Fix information available")

    if cveorg_fixed and osv_fixed:
        overlap = cveorg_fixed.intersection(osv_fixed)
        if overlap:
            score += 0.15
            versions = ", ".join(sorted(overlap)[:3])
            evidence.append(f"CVE.org and OSV agree on fixed version(s): {versions}")
        else:
            contradictions.append("CVE.org and OSV fixed-version data disagree")

    related = _products_match_packages(
        affected_products=(analysis.affected_products or []),
        packages=(analysis.packages or []),
    )
    if related:
        score += 0.1
        evidence.append("Product/package naming overlap across sources")

    if contradictions:
        score = max(0.0, score - 0.1)

    analysis.evidence_score = round(min(1.0, score), 2)
    analysis.evidence_links = evidence
    analysis.contradiction_flags = contradictions
    analysis.evidence_reason = "; ".join(evidence) if evidence else "No strong cross-source evidence."

    blended = min(1.0, (analysis.priority_score * 0.75) + (analysis.evidence_score * 0.25))
    analysis.priority_score = round(blended, 2)

    if analysis.evidence_reason:
        analysis.priority_reason = (
            f"{analysis.priority_reason}; evidence={analysis.evidence_score:.2f} ({analysis.evidence_reason})"
            if analysis.priority_reason
            else f"evidence={analysis.evidence_score:.2f} ({analysis.evidence_reason})"
        )

    return analysis


def _extract_cveorg_fixed_versions(entry: dict | None) -> set[str]:
    versions: set[str] = set()
    if not entry:
        return versions

    cna = entry.get("containers", {}).get("cna", {})
    for aff in cna.get("affected", []):
        for ver in aff.get("versions", []):
            status = str(ver.get("status", "")).lower()
            version = str(ver.get("version", "")).strip()
            if status == "fixed" and version:
                versions.add(version)
    return versions


def _extract_osv_fixed_versions(entry: dict | None) -> set[str]:
    versions: set[str] = set()
    if not entry:
        return versions

    for aff in entry.get("affected", []):
        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                fixed = str(event.get("fixed", "")).strip()
                if fixed:
                    versions.add(fixed)
    return versions


def _products_match_packages(affected_products: list[str], packages: list[str]) -> bool:
    package_tokens = {p.strip().lower() for p in packages if p and p.strip()}
    if not package_tokens:
        return False

    for ap in affected_products:
        normalized = str(ap).strip().lower()
        if not normalized:
            continue

        parts = [t for t in normalized.replace("/", " ").replace("-", " ").split() if t]
        if any(token in package_tokens for token in parts):
            return True

    return False


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
