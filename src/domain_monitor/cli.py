"""Command-line entry point for Domain Monitor."""
from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .app import create_app, default_data_dir, run_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="domain-monitor",
        description="Web tool to monitor suspicious look-alike domains and detect when "
                    "inactive domains go live again. Optional VirusTotal integration.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host/interface to bind to (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000,
                        help="TCP port to bind to (default: 5000).")
    parser.add_argument("--data-dir", default=None,
                        help=f"Directory where the SQLite database is stored "
                             f"(default: {default_data_dir()}).")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open the default web browser on startup.")
    parser.add_argument("--debug", action="store_true",
                        help="Run Flask in debug mode (developers only).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir).expanduser().resolve() if args.data_dir else default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    url = f"http://{args.host}:{args.port}"
    print(f"Domain Monitor v{__version__}")
    print(f"  Data dir : {data_dir}")
    print(f"  Listening: {url}")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    run_server(host=args.host, port=args.port, data_dir=data_dir, debug=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
