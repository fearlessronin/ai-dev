from __future__ import annotations

import argparse
import logging
from dataclasses import replace
from pathlib import Path

from .config import load_settings
from .demo import seed_demo_dataset
from .inventory import validate_inventory_file
from .polling import PollController
from .runner import CVEWatcher
from .web import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agentic AI CVE watcher")
    parser.add_argument(
        "mode",
        choices=["once", "daemon", "serve", "demo", "validate-inventory"],
        help="Run one pass, continuously, launch dashboard, or seed local demo data",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host for serve mode")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port for serve mode")
    parser.add_argument(
        "--poll",
        action="store_true",
        help="When used with serve mode, starts background API polling on startup",
    )
    parser.add_argument("--inventory-path", default=None, help="Inventory file path for validate-inventory mode")
    parser.add_argument(
        "--poll-interval-minutes",
        type=int,
        default=None,
        help="Optional polling interval override in minutes for daemon/polling modes",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    settings = load_settings()
    if args.poll_interval_minutes is not None:
        settings = replace(settings, poll_interval_minutes=max(1, args.poll_interval_minutes))

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
    elif args.mode == "validate-inventory":
        path_value = args.inventory_path or settings.asset_inventory_path
        result = validate_inventory_file(path_value)
        if result.get("ok"):
            logging.info("Inventory validation passed: %s", result.get("path"))
            logging.info("Inventory counts: %s", result.get("counts"))
            logging.info(
                "Inventory targets (preview): packages=%s ecosystems=%s cpes=%s",
                result["targets"]["packages"][:5],
                result["targets"]["ecosystems"][:5],
                result["targets"]["cpes"][:5],
            )
        else:
            logging.error("Inventory validation failed: %s", result.get("error"))
            raise SystemExit(1)
    else:
        poll_controller = PollController(
            watcher=watcher,
            output_dir=settings.output_dir,
            interval_minutes=settings.poll_interval_minutes,
            enabled=bool(args.poll),
        )
        poll_controller.start()

        root_dir = Path(__file__).resolve().parent.parent
        frontend_dir = root_dir / "frontend"
        docs_dir = root_dir / "docs"
        serve(
            frontend_dir=frontend_dir,
            output_dir=settings.output_dir,
            docs_dir=docs_dir,
            host=args.host,
            port=args.port,
            poll_controller=poll_controller,
        )


if __name__ == "__main__":
    main()
