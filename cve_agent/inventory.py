from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def load_inventory_targets(path_value: str | None) -> dict[str, list[str]]:
    if not path_value:
        return {"packages": [], "ecosystems": [], "cpes": []}
    path = Path(path_value).expanduser()
    try:
        suffix = path.suffix.lower()
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            return _from_json(data)
        if suffix == ".csv":
            return _from_csv(path)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {"packages": [], "ecosystems": [], "cpes": []}
    return {"packages": [], "ecosystems": [], "cpes": []}


def _from_json(data: Any) -> dict[str, list[str]]:
    if isinstance(data, dict):
        packages = _as_list(data.get("packages"))
        ecosystems = _as_list(data.get("ecosystems"))
        cpes = _as_list(data.get("cpes"))
        assets = data.get("assets")
        if isinstance(assets, list):
            p2, e2, c2 = _collect_assets(assets)
            packages.extend(p2)
            ecosystems.extend(e2)
            cpes.extend(c2)
        return _dedup(packages, ecosystems, cpes)
    if isinstance(data, list):
        p, e, c = _collect_assets(data)
        return _dedup(p, e, c)
    return {"packages": [], "ecosystems": [], "cpes": []}


def _from_csv(path: Path) -> dict[str, list[str]]:
    packages: list[str] = []
    ecosystems: list[str] = []
    cpes: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not isinstance(row, dict):
                continue
            packages.extend(_split_cell(row.get("package") or row.get("packages")))
            ecosystems.extend(_split_cell(row.get("ecosystem") or row.get("ecosystems")))
            cpes.extend(_split_cell(row.get("cpe") or row.get("cpes")))
    return _dedup(packages, ecosystems, cpes)


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
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []


def _dedup(packages: list[str], ecosystems: list[str], cpes: list[str]) -> dict[str, list[str]]:
    return {
        "packages": sorted(set(packages)),
        "ecosystems": sorted(set(ecosystems)),
        "cpes": sorted(set(cpes)),
    }
