"""Command-line entry point for running the HTTP API (``sn-analyzer-api``)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import logging

from .config import ConfigError, load_settings


def build_parser() -> argparse.ArgumentParser:
    """Build the parser for the API server's command-line options."""
    parser = argparse.ArgumentParser(description="Smart Network Anomaly Analyzer API")
    parser.add_argument(
        "--config", help="YAML configuration file (or set the SN_CONFIG_FILE variable)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument(
        "--cors-origin",
        action="append",
        dest="cors_origins",
        metavar="ORIGIN",
        help="Browser origin allowed to call the API; repeat for more than one "
        "(default: localhost:3000, for local development)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Load configuration, build the app, and run it under uvicorn."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        parser.error(str(exc))

    logging.basicConfig(
        level=getattr(logging, settings.logging.level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        import uvicorn
    except ImportError:
        parser.error(
            "uvicorn and fastapi are required to run the API; install them with "
            "'pip install \"smart-network-anomaly-analyzer[api]\"'"
        )

    from .api.app import create_app

    try:
        app = create_app(settings, cors_origins=args.cors_origins)
    except ValueError as exc:
        parser.error(str(exc))

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
