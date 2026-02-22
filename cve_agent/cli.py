from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .config import load_settings
from .demo import seed_demo_dataset
from .runner import CVEWatcher
from .web import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agentic AI CVE watcher")
    parser.add_argument(
        "mode",
        choices=["once", "daemon", "serve", "demo"],
        help="Run one pass, continuously, launch dashboard, or seed local demo data",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host for serve mode")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port for serve mode")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    settings = load_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    watcher = CVEWatcher(settings)
    if args.mode == "once":
        watcher.run_once()
    elif args.mode == "daemon":
        watcher.run_daemon()
    elif args.mode == "demo":
        target = seed_demo_dataset(settings.output_dir)
        logging.info("Demo dataset seeded at %s", target)
    else:
        root_dir = Path(__file__).resolve().parent.parent
        frontend_dir = root_dir / "frontend"
        docs_dir = root_dir / "docs"
        serve(
            frontend_dir=frontend_dir, output_dir=settings.output_dir, docs_dir=docs_dir, host=args.host, port=args.port
        )


if __name__ == "__main__":
    main()
