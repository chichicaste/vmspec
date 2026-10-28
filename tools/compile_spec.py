#!/usr/bin/env python3
"""Compile a .slaspec with Ghidra's SLEIGH compiler (phase-2 compile step).

Invokes the Ghidra ``sleigh`` compiler on a ``.slaspec`` and reports success or
the parse errors.  This is the ``compile`` step of the phase-2
compile-verify-retry loop: the deterministic skeleton compiles first, then each
constructor's P-Code semantics is filled in and re-compiled.

The compiler is ``sleigh.bat`` (Ghidra's ``SleighCompileLauncher``); its
Windows wrapper ends in a ``pause`` on error, so stdin is detached and a
timeout bounds the run.

Usage:
    python tools/compile_spec.py <spec.slaspec> [--sleigh PATH]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Known Ghidra SLEIGH compiler locations (searched in order when --sleigh is
# not given).
_DEFAULT_SLEIGH = [
    Path(r"C:\gnu\ghidra_12.2_PUBLIC\support\sleigh.bat"),
    Path(r"C:\gnu\ghidra\support\sleigh.bat"),
]


@dataclass
class CompileResult:
    """Outcome of a SLEIGH compilation."""

    ok: bool
    errors: list[str]
    output: str


def find_sleigh(explicit: str | None = None) -> Path:
    """Locate ``sleigh.bat``: *explicit* path, else the first known default."""
    if explicit is not None:
        return Path(explicit)
    for candidate in _DEFAULT_SLEIGH:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "sleigh.bat not found in the known Ghidra locations; pass --sleigh"
    )


def compile_slaspec(
    spec_path: str | Path,
    sleigh: str | Path | None = None,
    *,
    timeout: int = 120,
) -> CompileResult:
    """Compile *spec_path* and return the outcome.

    ``sleigh`` is the path to ``sleigh.bat`` (auto-detected when omitted).
    stdin is detached so the Windows ``pause`` (printed on error) returns
    immediately.
    """
    spec = Path(spec_path).resolve()
    compiler = Path(sleigh).resolve() if sleigh is not None else find_sleigh()
    try:
        proc = subprocess.run(
            [str(compiler), str(spec)],
            cwd=str(spec.parent),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CompileResult(ok=False, errors=["compilation timed out"], output="")
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    errors = [line.strip() for line in output.splitlines() if "ERROR" in line]
    return CompileResult(ok=proc.returncode == 0, errors=errors, output=output)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compile_spec.py",
        description="Compile a SLEIGH .slaspec with Ghidra's sleigh compiler.",
    )
    parser.add_argument("spec", help="path of the .slaspec to compile")
    parser.add_argument(
        "--sleigh",
        metavar="PATH",
        help="path to sleigh.bat (auto-detected when omitted)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    result = compile_slaspec(args.spec, args.sleigh)
    if result.ok:
        print(f"OK: {args.spec} compiled", file=sys.stderr)
        return 0
    print(f"FAILED: {args.spec}", file=sys.stderr)
    for line in result.errors:
        print(line, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
