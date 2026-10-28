#!/usr/bin/env python3
"""Deterministic SLEIGH skeleton generator (isa_recovery phase 1).

Loads a VMSpec config JSON and emits a fully-compiling ``.slaspec`` in which
every constructor ends in ``unimpl``.  No DSE, no state graph and no LLM are
involved: the structure and the rolling-key opcode patterns are computed
deterministically from the config's VM state + dispatch table.

Usage:
    python tools/gen_skeleton.py <config.json> [--out out.slaspec] [--engine ADDR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vmspec.config import load_config
from vmspec.skeleton import DEFAULT_ENGINE, generate_skeleton


def _parse_addr(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected a decimal or 0x-prefixed hex integer, got {value!r}"
        ) from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gen_skeleton.py",
        description=(
            "Emit a deterministic SLEIGH skeleton (all constructors unimpl) "
            "from a VMSpec config JSON."
        ),
    )
    parser.add_argument("config", help="path of the config JSON")
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="destination for the .slaspec (printed to stdout when omitted)",
    )
    parser.add_argument(
        "--engine",
        type=_parse_addr,
        default=None,
        metavar="ADDR",
        help=(
            "engine base address for the handler-offset lookup "
            "(default: the config's base_addr, else 0x1AE1000)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["rolling", "clear"],
        default="rolling",
        help=(
            "opcode encoding the constructors match: 'rolling' (encrypted, "
            "rolling key) or 'clear' (decrypted, constant byte=opcode)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    config = load_config(args.config)
    engine = (
        args.engine
        if args.engine is not None
        else (config.base_addr if config.base_addr is not None else DEFAULT_ENGINE)
    )

    spec, infos = generate_skeleton(
        config.vm_state,
        config.handlers,
        config.dispatch_table,
        engine=engine,
        mode=args.mode,
    )

    if args.out is not None:
        Path(args.out).write_text(spec, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(spec)

    n_analyzed = sum(1 for i in infos if i.handler is not None)
    n_operand = sum(1 for i in infos if i.operand_size)
    destination = args.out if args.out is not None else "stdout"
    print(f"constructors: {len(infos)} ({n_analyzed} analysed, "
          f"{n_operand} with operands)", file=sys.stderr)
    print(f"spec size   : {len(spec.encode('utf-8'))} bytes (.slaspec)", file=sys.stderr)
    print(f"output      : {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
