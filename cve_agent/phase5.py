from __future__ import annotations

from typing import Any

VENDOR_SOURCES = {"msrc", "red hat security data api", "debian security tracker"}


def _norm(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _cveorg_fixed_versions(entry: dict[str, Any] | None) -> list[str]:
    out: list[str] = []
    if not isinstance(entry, dict):
        return out
    cna = entry.get("containers", {}).get("cna", {})
    for aff in cna.get("affected", []):
        if not isinstance(aff, dict):
            continue
        for ver in aff.get("versions", []):
            if not isinstance(ver, dict):
                continue
            if str(ver.get("status", "")).strip().lower() != "fixed":
                continue
            fixed = str(ver.get("version", "")).strip()
            if fixed:
                out.append(fixed)
    return sorted(set(out))


def _osv_fixed_versions(entry: dict[str, Any] | None) -> list[str]:
    out: list[str] = []
    if not isinstance(entry, dict):
        return out
    for aff in entry.get("affected", []):
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges", []):
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events", []):
                if not isinstance(ev, dict):
                    continue
                fixed = str(ev.get("fixed", "")).strip()
                if fixed:
                    out.append(fixed)
    return sorted(set(out))


def _bool_label(flag: bool | None) -> str:
    if flag is None:
        return "unknown"
    return "yes" if flag else "no"


def _is_national_source(source: str) -> bool:
    s = _norm(source)
    if s in VENDOR_SOURCES:
        return False
    keywords = (
        "cisa",
        "cert-fr",
        "bsi",
        "cert-bund",
        "jvn",
        "ncsc",
        "govcert",
        "hkcert",
        "cert-eu",
    )
    return any(k in s for k in keywords)


def _source_family_flags(
    analysis: Any, cveorg_entry: dict[str, Any] | None, osv_entry: dict[str, Any] | None
) -> dict[str, bool]:
    regional = [_norm(s) for s in getattr(analysis, "regional_sources", [])]
    has_vendor = any(s in VENDOR_SOURCES for s in regional)
    has_national = any(_is_national_source(s) for s in regional)
    has_core = True  # NVD is the primary feed
    has_open = bool(cveorg_entry) or bool(osv_entry) or bool(getattr(analysis, "ghsa_ids", []))
    has_telemetry = bool(getattr(analysis, "epss_score", None) is not None) or bool(
        getattr(analysis, "kev_status", False)
    )
    return {
        "core": has_core,
        "vendor": has_vendor,
        "national": has_national,
        "open": has_open,
        "telemetry": has_telemetry,
    }


def _independent_sources(
    analysis: Any, cveorg_entry: dict[str, Any] | None, osv_entry: dict[str, Any] | None
) -> list[str]:
    sources: set[str] = {"NVD"}
    if cveorg_entry:
        sources.add("CVE.org")
    if osv_entry:
        sources.add("OSV")
    if getattr(analysis, "ghsa_ids", []):
        sources.add("GHSA")
    if getattr(analysis, "circl_sightings", None) is not None:
        sources.add("CIRCL")
    if getattr(analysis, "kev_status", False):
        sources.add("CISA KEV")
    if getattr(analysis, "epss_score", None) is not None:
        sources.add("EPSS")
    for src in getattr(analysis, "regional_sources", []):
        sources.add(str(src))
    return sorted(sources)


def _regional_escalation_badges(regional_sources: list[str]) -> list[str]:
    normalized = {_norm(s): str(s) for s in regional_sources}
    keys = set(normalized)

    cisa = any("cisa" in k for k in keys)
    cert_fr = any("cert-fr" in k for k in keys)
    bsi = any("bsi" in k or "cert-bund" in k for k in keys)
    eu = cert_fr or bsi or any("cert-eu" in k or "ncsc" in k for k in keys)
    national_count = sum(1 for k in keys if _is_national_source(k))

    badges: list[str] = []
    if national_count >= 2:
        badges.append("multi-national-corroboration")
    if national_count >= 3:
        badges.append("regional-burst")
    if cisa and eu:
        badges.append("transatlantic-escalation")
    if cisa and cert_fr:
        badges.append("CISA+CERT-FR")
    if cisa and bsi:
        badges.append("CISA+BSI")
    if cert_fr and bsi:
        badges.append("CERT-FR+BSI")
    return sorted(set(badges))


def _asset_mapping_hits(
    analysis: Any,
    target_packages: list[str],
    target_ecosystems: list[str],
    target_cpes: list[str],
) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    packages = [
        str(x)
        for x in (getattr(analysis, "packages", []) + getattr(analysis, "affected_products", []))
        if str(x).strip()
    ]
    ecosystems = [str(x) for x in getattr(analysis, "ecosystems", []) if str(x).strip()]
    cpes = [str(x) for x in getattr(analysis, "cpe_uris", []) if str(x).strip()]

    for target in target_packages:
        t = _norm(target)
        if not t:
            continue
        for value in packages:
            v = _norm(value)
            if t in v or v in t:
                key = ("package", target, value)
                if key not in seen:
                    hits.append({"match_type": "package", "target": target, "matched_value": value})
                    seen.add(key)

    for target in target_ecosystems:
        t = _norm(target)
        if not t:
            continue
        for value in ecosystems:
            if t == _norm(value):
                key = ("ecosystem", target, value)
                if key not in seen:
                    hits.append({"match_type": "ecosystem", "target": target, "matched_value": value})
                    seen.add(key)

    for target in target_cpes:
        t = _norm(target)
        if not t:
            continue
        for value in cpes:
            v = _norm(value)
            if v.startswith(t) or t in v:
                key = ("cpe", target, value)
                if key not in seen:
                    hits.append({"match_type": "cpe", "target": target, "matched_value": value})
                    seen.add(key)

    return hits


def _patch_matrix(
    analysis: Any,
    cveorg_entry: dict[str, Any] | None,
    osv_entry: dict[str, Any] | None,
    msrc_entry: dict[str, Any] | None,
    redhat_entry: dict[str, Any] | None,
    debian_entry: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    cveorg_fixes = _cveorg_fixed_versions(cveorg_entry)
    osv_fixes = _osv_fixed_versions(osv_entry)
    redhat_fixes = [
        str(x)
        for x in getattr(analysis, "fixed_versions", [])
        if str(x).startswith("RHSA-") or "red hat" in _norm(str(x))
    ]
    debian_fixes = [
        str(x)
        for x in getattr(analysis, "fixed_versions", [])
        if ":" in str(x) and any(rel in str(x).lower() for rel in ("bookworm", "bullseye", "buster", "sid", "trixie"))
    ]

    matrix = {
        "nvd": {"present": True, "fix_available": False, "evidence": "NVD candidate feed"},
        "cveorg": {
            "present": bool(cveorg_entry),
            "fix_available": bool(cveorg_fixes),
            "evidence": f"fixed_versions={len(cveorg_fixes)}",
        },
        "osv": {
            "present": bool(osv_entry),
            "fix_available": bool(osv_fixes),
            "evidence": f"fixed_events={len(osv_fixes)}",
        },
        "msrc": {
            "present": bool(msrc_entry),
            "fix_available": None,
            "evidence": "vendor advisory match" if msrc_entry else "none",
        },
        "redhat": {
            "present": bool(redhat_entry),
            "fix_available": bool(redhat_fixes),
            "evidence": f"fix_artifacts={len(redhat_fixes)}",
        },
        "debian": {
            "present": bool(debian_entry),
            "fix_available": bool(debian_fixes),
            "evidence": f"release_fixes={len(debian_fixes)}",
        },
    }
    matrix["vendor_any"] = {
        "present": bool(msrc_entry or redhat_entry or debian_entry),
        "fix_available": any(x.get("fix_available") is True for k, x in matrix.items() if k in {"redhat", "debian"}),
        "evidence": "MSRC/RedHat/Debian aggregate",
    }
    return matrix


def _patch_matrix_summary(matrix: dict[str, dict[str, Any]]) -> str:
    parts = []
    for key in ("nvd", "cveorg", "osv", "msrc", "redhat", "debian"):
        row = matrix.get(key, {})
        parts.append(
            f"{key.upper()}: present={_bool_label(row.get('present'))}, fix={_bool_label(row.get('fix_available'))}"
        )
    return " | ".join(parts)


def apply_phase5_features(
    analysis: Any,
    *,
    cveorg_entry: dict[str, Any] | None,
    osv_entry: dict[str, Any] | None,
    msrc_entry: dict[str, Any] | None,
    redhat_entry: dict[str, Any] | None,
    debian_entry: dict[str, Any] | None,
    target_ecosystems: list[str],
    target_packages: list[str],
    target_cpes: list[str],
) -> Any:
    independent = _independent_sources(analysis, cveorg_entry, osv_entry)
    family_flags = _source_family_flags(analysis, cveorg_entry, osv_entry)

    family_points = 0.0
    family_points += 0.20 if family_flags["core"] else 0.0
    family_points += 0.20 if family_flags["open"] else 0.0
    family_points += 0.25 if family_flags["vendor"] else 0.0
    family_points += 0.25 if family_flags["national"] else 0.0
    family_points += 0.10 if family_flags["telemetry"] else 0.0

    breadth_bonus = min(0.20, max(0, len(independent) - 2) * 0.03)
    score = round(min(1.0, family_points + breadth_bonus), 2)

    if score >= 0.8:
        confidence_label = "high"
    elif score >= 0.5:
        confidence_label = "medium"
    else:
        confidence_label = "low"

    badges = _regional_escalation_badges(list(getattr(analysis, "regional_sources", [])))
    asset_hits = _asset_mapping_hits(analysis, target_packages, target_ecosystems, target_cpes)
    asset_score = round(min(1.0, len(asset_hits) * 0.25), 2)
    patch_matrix = _patch_matrix(analysis, cveorg_entry, osv_entry, msrc_entry, redhat_entry, debian_entry)

    analysis.source_corroboration_count = len(independent)
    analysis.source_corroboration_score = score
    analysis.source_confidence_label = confidence_label
    analysis.source_corroboration_sources = independent
    analysis.source_family_presence = {k: bool(v) for k, v in family_flags.items()}
    analysis.vendor_advisory_count = sum(
        1 for s in getattr(analysis, "regional_sources", []) if _norm(s) in VENDOR_SOURCES
    )
    analysis.national_feed_count = sum(1 for s in getattr(analysis, "regional_sources", []) if _is_national_source(s))
    analysis.regional_escalation_badges = badges
    analysis.asset_mapping_hits = asset_hits
    analysis.asset_mapping_score = asset_score
    analysis.asset_mapping_summary = (
        "; ".join(f"{h['match_type']}:{h['target']}->{h['matched_value']}" for h in asset_hits[:5])
        or "no configured asset matches"
    )
    analysis.patch_availability_matrix = patch_matrix
    analysis.patch_availability_summary = _patch_matrix_summary(patch_matrix)
    return analysis
