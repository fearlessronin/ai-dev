from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str | None
    window_days: int
    poll_interval_minutes: int
    output_dir: Path
    state_file: Path
    log_level: str
    source_cache_ttl_minutes: int
    target_ecosystems: list[str]
    target_packages: list[str]
    reprocess_seen: bool


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

    return Settings(
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        window_days=max(1, int(os.getenv("WINDOW_DAYS", "30"))),
        poll_interval_minutes=max(1, int(os.getenv("POLL_INTERVAL_MINUTES", "60"))),
        output_dir=output_dir,
        state_file=Path(os.getenv("STATE_FILE", str(state_default))).resolve(),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        source_cache_ttl_minutes=max(1, int(os.getenv("SOURCE_CACHE_TTL_MINUTES", "15"))),
        target_ecosystems=_csv_env("TARGET_ECOSYSTEMS"),
        target_packages=_csv_env("TARGET_PACKAGES"),
        reprocess_seen=_bool_env("REPROCESS_SEEN", False),
    )
