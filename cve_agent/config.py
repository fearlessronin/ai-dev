from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .inventory import load_inventory_targets


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str | None
    github_token: str | None
    openvex_path: str | None
    window_days: int
    poll_interval_minutes: int
    output_dir: Path
    state_file: Path
    log_level: str
    source_cache_ttl_minutes: int
    target_ecosystems: list[str]
    target_packages: list[str]
    target_cpes: list[str]
    reprocess_seen: bool
    csaf_feed_urls: list[str]
    regional_rss_urls: list[str]
    jvn_api_template: str
    asset_inventory_path: str | None


def _csv_env(name: str) -> list[str]:
    raw = os.getenv(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    load_dotenv()

    output_dir = Path(os.getenv("OUTPUT_DIR", "output")).resolve()
    state_default = output_dir / "state.json"

    default_rss = [
        "https://www.cert.europa.eu/rss/advisories.xml",
        "https://www.govcert.gov.hk/en/rss.html",
        "https://www.hkcert.org/getrss",
    ]

    default_csaf = [
        "https://aggregator.certvde.com/",
        "https://advisories.ncsc.nl/service/",
    ]

    inventory_path = os.getenv("ASSET_INVENTORY_PATH") or None
    inventory_targets = load_inventory_targets(inventory_path)

    return Settings(
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        github_token=os.getenv("GITHUB_TOKEN") or None,
        openvex_path=os.getenv("OPENVEX_PATH") or None,
        window_days=max(1, int(os.getenv("WINDOW_DAYS", "30"))),
        poll_interval_minutes=max(1, int(os.getenv("POLL_INTERVAL_MINUTES", "60"))),
        output_dir=output_dir,
        state_file=Path(os.getenv("STATE_FILE", str(state_default))).resolve(),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        source_cache_ttl_minutes=max(1, int(os.getenv("SOURCE_CACHE_TTL_MINUTES", "15"))),
        target_ecosystems=sorted(set(_csv_env("TARGET_ECOSYSTEMS") + inventory_targets["ecosystems"])),
        target_packages=sorted(set(_csv_env("TARGET_PACKAGES") + inventory_targets["packages"])),
        target_cpes=sorted(set(_csv_env("TARGET_CPES") + inventory_targets["cpes"])),
        reprocess_seen=_bool_env("REPROCESS_SEEN", False),
        csaf_feed_urls=_csv_env("CSAF_FEED_URLS") or default_csaf,
        regional_rss_urls=_csv_env("REGIONAL_RSS_URLS") or default_rss,
        jvn_api_template=os.getenv(
            "JVN_API_TEMPLATE",
            "https://jvndb.jvn.jp/en/myjvn?method=getVulnOverviewList&cveId={cve_id}",
        ),
        asset_inventory_path=inventory_path,
    )
