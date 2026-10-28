"""Deterministic SLEIGH skeleton generation (isa_recovery phase 1).

Builds a fully-compiling ``.slaspec`` in which every instruction constructor
ends in ``unimpl``.  The structural parts -- endianness, address spaces, the
instruction token, the register file and the rolling-key context -- plus the
per-opcode rolling-key pattern are computed deterministically from the VM
configuration and the dispatch table; no DSE state graph and no LLM are
involved.

This mirrors the two-phase SLEIGH generator of ``infobyte/isa_recovery``:
phase 1 emits a deterministic skeleton of ``unimpl`` constructors that always
compiles, and a later phase fills in each constructor's P-Code semantics one
instruction at a time with a compile-verify-retry loop.

The skeleton models the single encrypted opcode byte.  Variable-length
operand bytes (``docs/SLEIGH.md`` §11) are a phase-2 encoding extension; the
operand size per handler is still recorded in :class:`ConstructorInfo` so
that phase can consume it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Handler, VMState
from .sleigh_gen import emit_header, encrypt_const, label

__all__ = ["ConstructorInfo", "generate_skeleton"]

# Operand size (bytes) per handler offset (``entry - engine``); 0 = no operand.
# Mirrors ``vmspec.operand._DECRYPTORS`` sizes, kept local so the skeleton does
# not depend on the DSE/decrypt layer.
_OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

# Default engine base address (the VM blob's mapping).  The handler offset used
# for the operand-size lookup is ``entry - engine``.
DEFAULT_ENGINE = 0x1AE1000


@dataclass
class ConstructorInfo:
    """Metadata for one emitted constructor (phase 2 fills in its P-Code)."""

    opcode: int              # decrypted opcode index (0..255)
    name: str                # SLEIGH constructor name
    handler: Handler | None  # analysed handler, or None for an unanalysed index
    encrypt_const: int       # C such that ``byte = C + key - 1``
    operand_size: int        # operand length in bytes (0 = no operand)


def _ctor_name(mnemonic: str, opcode: int) -> str:
    """Deterministic, unique constructor name for an opcode index.

    Analysed handlers use ``<mnemonic>_<opcode>``; unanalysed indices use
    ``op_<opcode>``.  The opcode index suffix guarantees uniqueness even when
    several indices share one handler body.
    """
    if mnemonic:
        return f"{label(mnemonic)}_{opcode:02X}"
    return f"op_{opcode:02X}"


def generate_skeleton(
    vm_state: VMState,
    handlers: list[Handler],
    dispatch_table: list[int] | None,
    *,
    engine: int = DEFAULT_ENGINE,
) -> tuple[str, list[ConstructorInfo]]:
    """Generate a deterministic SLEIGH skeleton and its constructor metadata.

    One constructor is emitted per opcode index (0..255) when *dispatch_table*
    is given, or per analysed handler using its canonical opcode otherwise.
    Each constructor matches the encrypted opcode byte with the rolling-key
    constraint ``byte = C + key - 1``, commits the key update
    ``key = key - opcode``, and ends in ``unimpl``.

    Returns ``(spec, infos)``: the ``.slaspec`` text and the per-constructor
    metadata for the phase-2 semantics pass.
    """
    analyzed_by_entry: dict[int, Handler] = {
        handler.entry: handler for handler in handlers
    }

    lines: list[str] = []
    lines.append("# VMSpec deterministic skeleton (.slaspec)")
    lines.append("# Phase 1 (isa_recovery): structure + unimpl stubs.")
    lines.append("# Phase 2 fills in each constructor's P-Code semantics.")
    lines.append("# Reference: arXiv:2610.29566")
    lines.append("")
    emit_header(lines, vm_state)

    infos: list[ConstructorInfo] = []

    def _emit_ctor(opcode: int, handler: Handler | None) -> None:
        mnemonic = handler.mnemonic if handler is not None else ""
        name = _ctor_name(mnemonic, opcode)
        offset = (handler.entry - engine) if handler is not None else 0
        operand_size = _OPERAND_LEN.get(offset, 0)
        c = encrypt_const(opcode)

        if handler is not None:
            lines.append(
                f"# opcode=0x{opcode:02X} -> {handler.mnemonic} "
                f"entry=0x{handler.entry:X} operand={operand_size}"
            )
        else:
            lines.append(f"# opcode=0x{opcode:02X} (unanalysed handler)")

        lines.append(
            f":{name} is byte = 0x{c:X} + key - 1 "
            f"[ key = key - 0x{opcode:02X}; globalset(inst_next, key); ] unimpl"
        )
        lines.append("")
        infos.append(
            ConstructorInfo(
                opcode=opcode,
                name=name,
                handler=handler,
                encrypt_const=c,
                operand_size=operand_size,
            )
        )

    if dispatch_table is None:
        for handler in handlers:
            _emit_ctor(handler.opcode, handler)
    else:
        for opcode in range(256):
            _emit_ctor(opcode, analyzed_by_entry.get(dispatch_table[opcode]))

    return "\n".join(lines).rstrip() + "\n", infos
