"""Command line entry point: ``python -m vmspec <binary> <config.json>``.

Loads the VM configuration, runs the full pipeline (DSE -> state tree ->
state graph -> SLEIGH) and writes the resulting ``.slaspec`` to ``--out``
(or to stdout when ``--out`` is omitted).  A short summary (number of
handlers and generated spec size in bytes) is printed to stderr.
"""

from __future__ import annotations

import argparse
import sys

from .config import load_config
from .pipeline import run_pipeline

__all__ = ["main"]

DEFAULT_MAX_STEPS = 100_000


def _build_parser() -> argparse.ArgumentParser:
    """Create the command line parser for ``python -m vmspec``."""
    parser = argparse.ArgumentParser(
        prog="python -m vmspec",
        description=(
            "Generate a SLEIGH .slaspec for a VM from a binary and a JSON "
            "configuration file (VMSpec pipeline: DSE -> state tree -> "
            "state graph -> SLEIGH)."
        ),
    )
    parser.add_argument(
        "binary",
        help="path of the binary containing the VM to analyse",
    )
    parser.add_argument(
        "config",
        help="path of the JSON configuration file (vpc, regions, handlers, ...)",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="destination for the .slaspec (printed to stdout when omitted)",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_MAX_STEPS,
        metavar="N",
        help=f"maximum DSE steps per handler (default: {DEFAULT_MAX_STEPS})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m vmspec``.

    Args:
        argv: Command line arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (0 on success).

    Raises:
        ValueError: If the configuration file is invalid.
        OSError: If the binary or the output file cannot be read/written.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.max_steps <= 0:
        parser.error("--max-steps must be a positive integer")

    vm_state, handlers = load_config(args.config)
    spec = run_pipeline(args.binary, vm_state, handlers, max_steps=args.max_steps)

    if args.out is not None:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(spec)
    else:
        sys.stdout.write(spec)

    print(f"handlers : {len(handlers)}", file=sys.stderr)
    print(f"spec size: {len(spec.encode('utf-8'))} bytes (.slaspec)", file=sys.stderr)
    destination = args.out if args.out is not None else "stdout"
    print(f"output   : {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())