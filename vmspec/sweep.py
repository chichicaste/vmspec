"""Flow-sensitive sweep of the VM bytecode keyed by ``(address, key)``.

This is the paper's §5.1 recursive-sweep made explicit: instead of a single
linear walk, the sweep explores a worklist of ``(addr, key)`` states with
memoization, following the fall-through and stopping at control-flow handlers.
Because the key is 32 bits (only its low byte drives the opcode decrypt), the
state space stays bounded and cannot path-explode.

The opcode decrypt uses the low byte of the key. The operand decrypt and the
per-handler key update are VM-specific and are supplied as a ``step`` callback,
so the sweep tracks the full 32-bit key (which the 2/4-byte operands and the
``jmp`` target need).

Key-conflict detection on joins is the soundness check: in a *correct* VM
program the key at an address is path-independent, so a join where two flows
commit different keys means a modelling bug or intentionally overlapping code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

__all__ = ["decrypt", "ror8", "SweepResult", "sweep"]

# ``step(op, addr, key, dbin) -> (next_addr, next_key, operand_clear)``.
StepFn = Callable[[int, int, int, bytes], tuple[int, int, bytes | None]]


def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def decrypt(byte: int, key: int) -> int:
    """Inverse of the dispatcher's opcode decryption (``key -= opcode``).

    ``key`` is the low byte of the rolling key.
    """
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
    key_at: dict[int, int] = field(default_factory=dict)  # full 32-bit key
    operand_at: dict[int, bytes] = field(default_factory=dict)
    # (addr, key_seen_first, key_conflicting)
    conflicts: list[tuple[int, int, int]] = field(default_factory=list)
    states: int = 0


def sweep(
    dbin: bytes,
    entry: int,
    initial_key: int,
    step: StepFn,
    *,
    control_flow: frozenset[int] = frozenset({0x304, 0x7E9}),
    max_states: int = 100_000,
) -> SweepResult:
    """Recover the ``addr -> (opcode, key, operand)`` map over the bytecode.

    Args:
        dbin: Raw blob bytes.
        entry: Bytecode program entry offset.
        initial_key: Full 32-bit rolling key at ``entry``.
        step: ``(op, addr, key, dbin) -> (next_addr, next_key, operand_clear)``;
            decrypts the operand and applies the handler's key update.
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
        op = decrypt(byte, key & 0xFF)
        result.key_at[addr] = key
        result.opcode_at[addr] = op

        # dispatcher update: low byte -= opcode
        key = (key & ~0xFF) | ((key & 0xFF) - op & 0xFF)
        if op in control_flow:
            continue

        next_addr, key, operand_clear = step(op, addr, key, dbin)
        result.operand_at[addr] = operand_clear
        work.append((next_addr, key))

    return result
