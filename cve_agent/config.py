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


def load_settings() -> Settings:
    load_dotenv()

    output_dir = Path(os.getenv("OUTPUT_DIR", "output")).resolve()
    state_default = output_dir / "state.json"

    return Settings(
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        window_days=max(1, int(os.getenv("WINDOW_DAYS", "10"))),
        poll_interval_minutes=max(1, int(os.getenv("POLL_INTERVAL_MINUTES", "60"))),
        output_dir=output_dir,
        state_file=Path(os.getenv("STATE_FILE", str(state_default))).resolve(),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
