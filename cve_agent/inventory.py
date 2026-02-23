from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _empty_targets() -> dict[str, list[str]]:
    return {"packages": [], "ecosystems": [], "cpes": []}


def _empty_context() -> dict[str, Any]:
    return {"targets": _empty_targets(), "assets": []}


def load_inventory_targets(path_value: str | None) -> dict[str, list[str]]:
    return dict(load_inventory_context(path_value).get("targets", _empty_targets()))


def load_inventory_context(path_value: str | None) -> dict[str, Any]:
    if not path_value:
        return _empty_context()
    path = Path(path_value).expanduser()
    try:
        suffix = path.suffix.lower()
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            return _normalize_context(_from_json(data))
        if suffix == ".csv":
            return _normalize_context(_from_csv(path))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return _empty_context()
    return _empty_context()


def _from_json(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        targets = {
            "packages": _as_list(data.get("packages")),
            "ecosystems": _as_list(data.get("ecosystems")),
            "cpes": _as_list(data.get("cpes")),
        }
        assets_raw = data.get("assets") if isinstance(data.get("assets"), list) else []
        assets = [_normalize_asset_record(item) for item in assets_raw if isinstance(item, dict)]
        return {"targets": targets, "assets": assets}
    if isinstance(data, list):
        assets = [_normalize_asset_record(item) for item in data if isinstance(item, dict)]
        return {"targets": _empty_targets(), "assets": assets}
    return _empty_context()


def _from_csv(path: Path) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            if not isinstance(row, dict):
                continue
            asset = _normalize_asset_record(
                {
                    "asset_id": row.get("asset_id") or row.get("id") or f"row-{idx}",
                    "package": row.get("package") or row.get("packages"),
                    "ecosystem": row.get("ecosystem") or row.get("ecosystems"),
                    "cpe": row.get("cpe") or row.get("cpes"),
                    "owner": row.get("owner"),
                    "criticality": row.get("criticality"),
                    "environment": row.get("environment"),
                    "business_service": row.get("business_service") or row.get("service"),
                    "internet_exposed": row.get("internet_exposed") or row.get("public_exposure"),
                    "tags": row.get("tags"),
                }
            )
            assets.append(asset)
    return {"targets": _empty_targets(), "assets": assets}


def _normalize_asset_record(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": str(item.get("asset_id") or item.get("id") or "").strip(),
        "packages": _as_list(item.get("package") or item.get("packages")),
        "ecosystems": _as_list(item.get("ecosystem") or item.get("ecosystems")),
        "cpes": _as_list(item.get("cpe") or item.get("cpes")),
        "owner": str(item.get("owner") or "").strip(),
        "criticality": str(item.get("criticality") or "").strip().lower(),
        "environment": str(item.get("environment") or "").strip().lower(),
        "business_service": str(item.get("business_service") or item.get("service") or "").strip(),
        "internet_exposed": _as_bool(item.get("internet_exposed") or item.get("public_exposure")),
        "tags": _as_list(item.get("tags")),
    }


def _normalize_context(ctx: dict[str, Any]) -> dict[str, Any]:
    targets = ctx.get("targets") if isinstance(ctx.get("targets"), dict) else _empty_targets()
    assets = [dict(a) for a in ctx.get("assets", []) if isinstance(a, dict)]
    p2, e2, c2 = _collect_assets(assets)
    targets = _dedup(
        _as_list(targets.get("packages")) + p2,
        _as_list(targets.get("ecosystems")) + e2,
        _as_list(targets.get("cpes")) + c2,
    )
    return {"targets": targets, "assets": assets}


def _collect_assets(items: list[Any]) -> tuple[list[str], list[str], list[str]]:
    packages: list[str] = []
    ecosystems: list[str] = []
    cpes: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        packages.extend(_as_list(item.get("package") or item.get("packages")))
        ecosystems.extend(_as_list(item.get("ecosystem") or item.get("ecosystems")))
        cpes.extend(_as_list(item.get("cpe") or item.get("cpes")))
    return packages, ecosystems, cpes


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_cell(value: str | None) -> list[str]:
    if not value:
        return []
    out: list[str] = []
    for part in str(value).replace(";", ",").split(","):
        x = part.strip()
        if x:
            out.append(x)
    return out


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return _split_cell(value)
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []


def _dedup(packages: list[str], ecosystems: list[str], cpes: list[str]) -> dict[str, list[str]]:
    return {
        "packages": sorted(set(packages)),
        "ecosystems": sorted(set(ecosystems)),
        "cpes": sorted(set(cpes)),
    }


def validate_inventory_file(path_value: str | None) -> dict[str, Any]:
    path_text = str(path_value or "").strip()
    if not path_text:
        return {"ok": False, "error": "path is required", "targets": _empty_targets()}
    path = Path(path_text).expanduser()
    if not path.exists() or not path.is_file():
        return {"ok": False, "error": f"file not found: {path}", "targets": _empty_targets()}
    context = load_inventory_context(str(path))
    targets = context.get("targets", _empty_targets())
    assets = context.get("assets", [])
    total = len(targets["packages"]) + len(targets["ecosystems"]) + len(targets["cpes"])
    if total == 0:
        return {"ok": False, "error": "no inventory targets parsed", "targets": targets}
    criticalities = sorted(
        {str(a.get("criticality")) for a in assets if isinstance(a, dict) and str(a.get("criticality", ""))}
    )
    environments = sorted(
        {str(a.get("environment")) for a in assets if isinstance(a, dict) and str(a.get("environment", ""))}
    )
    return {
        "ok": True,
        "path": str(path.resolve()),
        "targets": targets,
        "counts": {
            "packages": len(targets["packages"]),
            "ecosystems": len(targets["ecosystems"]),
            "cpes": len(targets["cpes"]),
            "assets": len([a for a in assets if any(a.get(k) for k in ("packages", "ecosystems", "cpes"))]),
        },
        "metadata": {
            "criticalities": criticalities,
            "environments": environments,
        },
    }
