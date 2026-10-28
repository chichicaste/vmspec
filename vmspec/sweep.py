"""Flow-sensitive sweep of the VM bytecode keyed by ``(address, key)``.

This is the paper's §5.1 recursive-sweep made explicit: instead of a single
linear walk, the sweep explores a worklist of ``(addr, key)`` states with
memoization, following the fall-through and stopping at control-flow handlers.
Because the key is 8 bits, there are at most 256 distinct keys per address, so
the sweep terminates and cannot path-explode.

Key-conflict detection on joins is the soundness check GLM identified: in a
*correct* VM program the key at an address is path-independent (the bytes are
fixed and the correct decode must be reproducible on every path), so a join
where two flows commit different keys means a modelling bug or intentionally
overlapping code — both of which should be surfaced, not hidden.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

__all__ = ["decrypt", "ror8", "SweepResult", "sweep"]


def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def decrypt(byte: int, key: int) -> int:
    """Inverse of the dispatcher's opcode decryption (``key -= opcode``)."""
    cl = (byte - key) & 0xFF
    cl = (cl + 1) & 0xFF
    cl = ror8(cl, 4)
    cl = (cl - 0x85) & 0xFF
    cl = (~cl) & 0xFF
    return cl


@dataclass
class SweepResult:
    """Output of :func:`sweep`."""

    opcode_at: dict[int, int] = field(default_factory=dict)
    key_at: dict[int, int] = field(default_factory=dict)
    # (addr, key_seen_first, key_conflicting)
    conflicts: list[tuple[int, int, int]] = field(default_factory=list)
    states: int = 0


def sweep(
    dbin: bytes,
    entry: int,
    initial_key: int,
    operand_len: Callable[[int], int],
    *,
    control_flow: frozenset[int] = frozenset({0x304, 0x7E9}),
    max_states: int = 100_000,
) -> SweepResult:
    """Recover the ``addr -> (opcode, key)`` map over the bytecode.

    Args:
        dbin: Raw blob bytes.
        entry: Bytecode program entry offset.
        initial_key: Rolling key at ``entry`` (low byte).
        operand_len: ``opcode -> operand byte length`` (VM-specific).
        control_flow: Opcodes whose computed target the sweep cannot follow
            (``jmp`` 0x304 / ``ret_native`` 0x7E9); they terminate a path.
        max_states: Safety bound on the number of ``(addr, key)`` states.
    """
    result = SweepResult()
    work: list[tuple[int, int]] = [(entry, initial_key)]
    seen: set[tuple[int, int]] = set()

    while work and result.states < max_states:
        addr, key = work.pop()
        if (addr, key) in seen:
            continue
        seen.add((addr, key))
        result.states += 1
        if addr >= len(dbin):
            continue

        if addr in result.key_at and result.key_at[addr] != key:
            result.conflicts.append((addr, result.key_at[addr], key))
            continue

        byte = dbin[addr]
        op = decrypt(byte, key)
        result.key_at[addr] = key
        result.opcode_at[addr] = op

        if op in control_flow:
            continue  # branch/terminal: computed target not followed here
        work.append((addr + 1 + operand_len(op), (key - op) & 0xFF))

    return result
