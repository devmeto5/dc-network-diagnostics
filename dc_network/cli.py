"""CLI: an explicit config is required before live network checks."""

import argparse
from pathlib import Path
import sys

from .config import load
from .reporting import EXIT, make_report, render
from .runner import collect, demo


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit-target DNS, TCP, and TLS diagnostics")
    parser.add_argument("--version", action="version", version="DC Network Diagnostics 0.1.0")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Synthetic examples; no network connections")
    mode.add_argument("--config", type=Path, help="TOML file authorizing explicit live targets")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("--output", type=Path, help="New report file; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        endpoints = demo() if args.demo else collect(load(args.config))
        data = make_report(endpoints, "DEMO" if args.demo else "LIVE")
        output = render(data, args.format)
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(output)
        else:
            print(output, end="")
        return EXIT[data["status"]]
    except (OSError, ValueError, UnicodeError) as error:
        print(f"dc-network: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
