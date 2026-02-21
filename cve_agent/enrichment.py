from __future__ import annotations

from .models import AnalysisResult


def apply_enrichment(
    analysis: AnalysisResult,
    kev_entry: dict | None,
    epss_entry: dict | None,
    cveorg_entry: dict | None,
    osv_entry: dict | None,
    ghsa_entries: list[dict] | None = None,
    circl_entry: dict | None = None,
    openvex_status: str | None = None,
    regional_sources: list[str] | None = None,
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

    if ghsa_entries:
        _apply_ghsa(analysis, ghsa_entries)

    if circl_entry:
        _apply_circl(analysis, circl_entry)

    if openvex_status:
        analysis.openvex_status = openvex_status

    if regional_sources:
        analysis.regional_sources.extend(regional_sources)

    analysis.cpe_uris = sorted(set(analysis.cpe_uris + (analysis.cve.cpes or [])))
    analysis.affected_products = sorted(set(analysis.affected_products))
    analysis.ecosystems = sorted(set(analysis.ecosystems))
    analysis.packages = sorted(set(analysis.packages))
    analysis.fixed_versions = sorted(set(analysis.fixed_versions))
    analysis.ghsa_ids = sorted(set(analysis.ghsa_ids))
    analysis.regional_sources = sorted(set(analysis.regional_sources))
    analysis.regional_signal_count = len(analysis.regional_sources)
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

    _apply_vulnrichment(analysis, entry)


def _apply_vulnrichment(analysis: AnalysisResult, entry: dict) -> None:
    adp_entries = entry.get("containers", {}).get("adp", [])
    for adp in adp_entries:
        if not isinstance(adp, dict):
            continue
        metrics = adp.get("metrics", [])
        for metric in metrics:
            if not isinstance(metric, dict):
                continue

            for key in ("ssvc", "other"):
                payload = metric.get(key)
                if isinstance(payload, dict):
                    decision = str(payload.get("decision", "")).strip()
                    role = str(payload.get("role", "")).strip()
                    if decision and not analysis.ssvc_decision:
                        analysis.ssvc_decision = decision
                    if role and not analysis.ssvc_role:
                        analysis.ssvc_role = role


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


def _apply_ghsa(analysis: AnalysisResult, entries: list[dict]) -> None:
    severity_rank = {"low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}
    best_severity = analysis.ghsa_severity or ""

    for item in entries:
        ghsa_id = str(item.get("ghsa_id", "")).strip()
        if ghsa_id:
            analysis.ghsa_ids.append(ghsa_id)

        sev = str(item.get("severity", "")).strip().lower()
        if sev and severity_rank.get(sev, 0) > severity_rank.get(best_severity.lower(), 0):
            best_severity = sev

        for vuln in item.get("vulnerabilities", []):
            pkg = vuln.get("package", {}) if isinstance(vuln, dict) else {}
            ecosystem = str(pkg.get("ecosystem", "")).strip()
            name = str(pkg.get("name", "")).strip()
            if ecosystem:
                analysis.ecosystems.append(ecosystem)
            if name:
                analysis.packages.append(name)

            patched = str(vuln.get("patched_versions", "")).strip()
            if patched:
                analysis.fixed_versions.append(patched)

    if best_severity:
        analysis.ghsa_severity = best_severity


def _apply_circl(analysis: AnalysisResult, entry: dict) -> None:
    sightings = entry.get("sightings")
    if isinstance(sightings, int):
        analysis.circl_sightings = sightings
        return

    if isinstance(sightings, list):
        analysis.circl_sightings = len(sightings)
        return

    if isinstance(sightings, dict):
        total = 0
        for v in sightings.values():
            if isinstance(v, int):
                total += v
            elif isinstance(v, list):
                total += len(v)
        if total > 0:
            analysis.circl_sightings = total


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

    if analysis.regional_signal_count > 0:
        score += min(0.08, analysis.regional_signal_count * 0.02)
        reasons.append(f"Regional signals={analysis.regional_signal_count}")

    if analysis.cve.cvss_v31_base is not None:
        cvss_component = min(0.15, (analysis.cve.cvss_v31_base / 10.0) * 0.15)
        score += cvss_component
        reasons.append(f"CVSS={analysis.cve.cvss_v31_base:.1f}")

    analysis.priority_score = round(min(1.0, score), 2)
    analysis.priority_reason = "; ".join(reasons)
