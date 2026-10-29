#!/usr/bin/env python3
"""Package the clear SLEIGH spec as a Ghidra processor module (phase 6).

Assembles the ``vmspec`` processor module (Module.manifest + .ldefs/.pspec/
.cspec + the generated clear .slaspec + the compiled .sla), then optionally
installs it into the Ghidra Processors directory so ``analyzeHeadless`` can
load the ``vmspec:LE:32:default`` language.

This turns the manual phase-6 packaging into one reproducible step. The only
generated artifacts are the ``.slaspec`` (from :func:`vmspec.skeleton.
generate_skeleton` ``mode="clear"``) and the ``.sla`` (compiled by Ghidra's
``sleigh`` compiler); every other module file is a fixed constant.

Usage::

    python tools/package_proc.py <config.json> [--ghidra DIR] [--install] [--out DIR]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from vmspec.config import load_config
from vmspec.semantics import handler_pcode
from vmspec.skeleton import generate_skeleton

ENGINE = 0x1AE1000
DEFAULT_GHIDRA = Path(r"C:\gnu\ghidra_12.2_PUBLIC")
DEFAULT_OUT = Path("data/vmspec-proc")

# Fixed processor-module files (Ghidra 12.2).  The clear spec carries no
# context variable, so the .pspec has no <context_data>.
_MODULE_MANIFEST = """MODULE FILE LICENSE: MIT
MODULE NAME: vmspec
MODULE DEPENDENCIES:
"""

_EXTENSION_PROPERTIES = """name=vmspec
description=VMSpec clear-encoding bytecode VM processor (VMSpec paper)
author=chichicaste
createdOn=2026-10-27
version=1.0
"""

_LDEFS = """<?xml version="1.0" encoding="UTF-8"?>

<language_definitions>
  <language processor="vmspec"
            endian="little"
            size="32"
            variant="default"
            version="1.0"
            slafile="vmspec.sla"
            processorspec="vmspec.pspec"
            id="vmspec:LE:32:default">
    <description>VMSpec clear-encoding bytecode VM</description>
    <compiler name="default" spec="vmspec.cspec" id="default"/>
  </language>
</language_definitions>
"""

_PSPEC = """<?xml version="1.0" encoding="UTF-8"?>

<processor_spec>
  <programcounter register="VPC"/>
</processor_spec>
"""

_CSPEC = """<?xml version="1.0" encoding="UTF-8"?>

<compiler_spec>
  <data_organization>
    <absolute_max_alignment value="0" />
    <machine_alignment value="1" />
    <default_alignment value="1" />
    <default_pointer_alignment value="4" />
    <pointer_size value="4" />
    <wchar_size value="2" />
    <short_size value="2" />
    <integer_size value="4" />
    <long_size value="4" />
    <long_long_size value="8" />
    <float_size value="4" />
    <double_size value="8" />
    <long_double_size value="8" />
    <size_alignment_map>
      <entry size="1" alignment="1" />
      <entry size="2" alignment="2" />
      <entry size="4" alignment="4" />
      <entry size="8" alignment="8" />
    </size_alignment_map>
  </data_organization>
  <stackpointer register="VSP" space="ram"/>
  <!-- The decompiler's global scope: without a <global> range the native
       decompiler marks no space as global, never queries the symbol table
       and DecompInterface fails with "Bad decompile address: r0x...". -->
  <global>
    <range space="ram"/>
  </global>
  <default_proto>
    <prototype name="default" extrapop="0" stackshift="0">
      <input/>
      <output/>
    </prototype>
  </default_proto>
</compiler_spec>
"""


def assemble(config, engine: int, out_dir: Path) -> Path:
    """Write the module files (fixed + generated .slaspec) into *out_dir*.

    Returns the language directory holding the ``.slaspec`` (the compile
    target).
    """
    lang_dir = out_dir / "data" / "languages"
    lang_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "Module.manifest").write_text(_MODULE_MANIFEST, newline="\n")
    (out_dir / "extension.properties").write_text(_EXTENSION_PROPERTIES, newline="\n")
    (lang_dir / "vmspec.ldefs").write_text(_LDEFS, newline="\n")
    (lang_dir / "vmspec.pspec").write_text(_PSPEC, newline="\n")
    (lang_dir / "vmspec.cspec").write_text(_CSPEC, newline="\n")
    spec, _infos = generate_skeleton(
        config.vm_state,
        config.handlers,
        config.dispatch_table,
        engine=engine,
        mode="clear",
        semantics=handler_pcode,
    )
    (lang_dir / "vmspec.slaspec").write_text(spec, newline="\n")
    return lang_dir


def _find_sleigh(ghidra: Path) -> Path:
    candidate = ghidra / "support" / "sleigh.bat"
    if not candidate.exists():
        raise FileNotFoundError(f"sleigh.bat not found under {ghidra}")
    return candidate


def compile_sla(lang_dir: Path, ghidra: Path) -> None:
    """Compile vmspec.slaspec -> vmspec.sla with Ghidra's sleigh compiler."""
    spec = (lang_dir / "vmspec.slaspec").resolve()
    sleigh = _find_sleigh(ghidra)
    proc = subprocess.run(
        [str(sleigh), str(spec)],
        cwd=str(spec.parent),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=180,
    )
    if proc.returncode != 0:
        errors = [l.strip() for l in (proc.stdout + "\n" + proc.stderr).splitlines() if "ERROR" in l]
        raise SystemExit(
            "sleigh compilation failed:\n" + "\n".join(errors)
        )
    if not (lang_dir / "vmspec.sla").exists():
        raise SystemExit("sleigh produced no vmspec.sla")


def install(module_dir: Path, ghidra: Path) -> None:
    """Copy the module into <ghidra>/Ghidra/Processors/vmspec, removing any
    stale copy (and any colliding Extensions/vmspec)."""
    processors = ghidra / "Ghidra" / "Processors" / "vmspec"
    extension = ghidra / "Ghidra" / "Extensions" / "vmspec"
    for stale in (processors, extension):
        if stale.exists():
            import shutil

            shutil.rmtree(stale)
    import shutil

    shutil.copytree(module_dir, processors)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="package_proc.py",
        description="Package the clear SLEIGH spec as a Ghidra processor module.",
    )
    parser.add_argument("config", help="path of the config JSON")
    parser.add_argument(
        "--ghidra",
        type=Path,
        default=DEFAULT_GHIDRA,
        metavar="DIR",
        help=f"Ghidra install directory (default: {DEFAULT_GHIDRA})",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        metavar="DIR",
        help=f"module output directory (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="install the module into <ghidra>/Ghidra/Processors/vmspec",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    config = load_config(args.config)
    engine = config.base_addr or ENGINE

    lang_dir = assemble(config, engine, args.out)
    compile_sla(lang_dir, args.ghidra)
    print(f"assembled + compiled: {args.out} (256 constructors)")

    if args.install:
        install(args.out, args.ghidra)
        print(f"installed: {args.ghidra / 'Ghidra' / 'Processors' / 'vmspec'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
