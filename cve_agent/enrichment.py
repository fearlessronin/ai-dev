from __future__ import annotations

from .models import AnalysisResult


def apply_enrichment(
    analysis: AnalysisResult,
    kev_entry: dict | None,
    epss_entry: dict | None,
    cveorg_entry: dict | None,
    osv_entry: dict | None,
) -> AnalysisResult:
    if kev_entry:
        analysis.kev_status = True
        analysis.kev_date_added = str(kev_entry.get("dateAdded", "")) or None
        analysis.kev_due_date = str(kev_entry.get("dueDate", "")) or None
        analysis.kev_required_action = str(kev_entry.get("requiredAction", "")) or None

    if epss_entry:
        analysis.epss_score = float(epss_entry.get("epss_score", 0.0))
        analysis.epss_percentile = float(epss_entry.get("epss_percentile", 0.0))

    if cveorg_entry:
        _apply_cveorg(analysis, cveorg_entry)

    if osv_entry:
        _apply_osv(analysis, osv_entry)

    analysis.affected_products = sorted(set(analysis.affected_products))
    analysis.ecosystems = sorted(set(analysis.ecosystems))
    analysis.packages = sorted(set(analysis.packages))
    analysis.fixed_versions = sorted(set(analysis.fixed_versions))
    analysis.has_fix = len(analysis.fixed_versions) > 0

    _assign_priority(analysis)
    return analysis


def _apply_cveorg(analysis: AnalysisResult, entry: dict) -> None:
    cna = entry.get("containers", {}).get("cna", {})
    provider = cna.get("providerMetadata", {})

    org_id = str(provider.get("orgId", "")).strip()
    if org_id:
        analysis.cna_org_id = org_id

    for aff in cna.get("affected", []):
        vendor = str(aff.get("vendor", "")).strip()
        product = str(aff.get("product", "")).strip()
        if vendor or product:
            analysis.affected_products.append(f"{vendor}/{product}".strip("/"))

        for ver in aff.get("versions", []):
            status = str(ver.get("status", "")).lower()
            if status != "fixed":
                continue
            fixed = str(ver.get("version", "")).strip()
            if fixed:
                analysis.fixed_versions.append(fixed)


def _apply_osv(analysis: AnalysisResult, entry: dict) -> None:
    for aff in entry.get("affected", []):
        pkg = aff.get("package", {})
        ecosystem = str(pkg.get("ecosystem", "")).strip()
        name = str(pkg.get("name", "")).strip()

        if ecosystem:
            analysis.ecosystems.append(ecosystem)
        if name:
            analysis.packages.append(name)

        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                fixed = str(event.get("fixed", "")).strip()
                if fixed:
                    analysis.fixed_versions.append(fixed)


def _assign_priority(analysis: AnalysisResult) -> None:
    score = 0.0
    reasons: list[str] = []

    ai_component = min(0.45, analysis.confidence * 0.45)
    score += ai_component
    reasons.append(f"AI relevance={analysis.confidence:.2f}")

    if analysis.epss_score is not None:
        epss_component = min(0.30, analysis.epss_score * 0.30)
        score += epss_component
        reasons.append(f"EPSS={analysis.epss_score:.3f}")

    if analysis.kev_status:
        score += 0.20
        reasons.append("KEV listed")

    if analysis.has_fix:
        score += 0.05
        reasons.append("Fix available")

    if analysis.cve.cvss_v31_base is not None:
        cvss_component = min(0.15, (analysis.cve.cvss_v31_base / 10.0) * 0.15)
        score += cvss_component
        reasons.append(f"CVSS={analysis.cve.cvss_v31_base:.1f}")

    analysis.priority_score = round(min(1.0, score), 2)
    analysis.priority_reason = "; ".join(reasons)
