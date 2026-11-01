"""Handler analysis -> VM ISA IR -> SLEIGH orchestration."""

from __future__ import annotations

import warnings
from collections.abc import Callable

import angr

from .dse import analyze_handler
from .model import GraphNode, Handler, VMState
from .ir import ISA
from .ir_lowering import lower_isa
from .sleigh_gen import generate_sleigh
from .state_graph import build_state_graph

__all__ = ["recover_isa", "run_pipeline"]


def recover_isa(
    binary_path: str,
    vm_state: VMState,
    handlers: list[Handler],
    *,
    max_steps: int = 100_000,
    base_addr: int | None = None,
    arch: str = "x86",
    dispatch_table: list[int] | None = None,
    opcode_encoder: Callable | None = None,
) -> ISA:
    """Analyze handlers and return independent IR for any consumer."""
    if base_addr is not None:
        project = angr.Project(
            binary_path,
            auto_load_libs=False,
            main_opts={"backend": "blob", "base_addr": base_addr, "arch": arch},
        )
    else:
        project = angr.Project(binary_path, auto_load_libs=False)

    built: list[tuple[Handler, GraphNode]] = []
    for handler in handlers:
        state_root = analyze_handler(project, handler, vm_state, max_steps=max_steps)
        if state_root is None:
            warnings.warn(
                f"handler opcode=0x{handler.opcode:X} entry=0x{handler.entry:X} "
                "produced no DSE states; it is omitted from the recovered ISA",
                stacklevel=2,
            )
            continue
        built.append((handler, build_state_graph(state_root)))

    return lower_isa(built, vm_state, dispatch_table, opcode_encoder=opcode_encoder)


def run_pipeline(
    binary_path: str,
    vm_state: VMState,
    handlers: list[Handler],
    *,
    max_steps: int = 100_000,
    base_addr: int | None = None,
    arch: str = "x86",
    dispatch_table: list[int] | None = None,
    opcode_encoder: Callable | None = None,
) -> str:
    """Recover the VM ISA IR, then pass it to the SLEIGH backend."""
    isa = recover_isa(
        binary_path, vm_state, handlers, max_steps=max_steps, base_addr=base_addr,
        arch=arch, dispatch_table=dispatch_table, opcode_encoder=opcode_encoder,
    )
    return generate_sleigh(isa)
