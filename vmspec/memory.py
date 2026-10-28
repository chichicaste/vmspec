"""Custom symbolic memory model — the core VMSpec technique.

VMSpec's DSE never concretizes symbolic pointers: every read through a symbolic
address produces a fresh symbolic variable (rather than forking over concrete
candidate values). This is implemented on top of angr's ``state.inspect``
breakpoints, with a per-state recorder (a ``SimStatePlugin``) that is copied on
state fork so each path keeps its own list of memory operations and calls.

Reference: arXiv:2610.29566, §4.2 (Memory Model).
"""

from __future__ import annotations

import angr

from .model import Call, MemAccess


class Recorder(angr.SimStatePlugin):
    """Per-state record of memory ops and calls; copied on state fork."""

    def __init__(self) -> None:
        super().__init__()
        self.mem_ops: list[MemAccess] = []
        self.calls: list[Call] = []

    @property
    def NAME(self) -> str:
        return "vmspec_recorder"

    def copy(self, memo):  # noqa: D102
        c = Recorder()
        c.mem_ops = list(self.mem_ops)
        c.calls = list(self.calls)
        return c

    def merge(self, others, merge_conditions, common_ancestor=None):  # noqa: D102
        # VMSpec explores all paths; never merge states.
        return False

    def widen(self, others):  # noqa: D102
        return False


def _fresh_read_var(state: angr.SimState, bits: int):
    """Return a fresh, unconstrained bitvector of `bits` bits."""
    return state.solver.BVS("vmspec_mem_read", bits)


def install(state: angr.SimState, read_only_ranges: tuple[tuple[int, int], ...] = ()) -> Recorder:
    """Install the no-concretization memory model on `state` (and its forks).

    - ``mem_read`` (before): if the address is symbolic, override the result
      with a fresh symbolic variable instead of concretizing the pointer.
    - ``mem_read`` (after): record ``(addr, result, length)``.
    - ``mem_write`` (after): record ``(addr, value, length)``.

    ``read_only_ranges`` is reserved for the paper's exception (reads from
    read-only memory may use the concrete value); the current implementation
    treats all symbolic reads uniformly.

    Returns the :class:`Recorder` plugin; access it later via
    ``state.vmspec_recorder``.
    """
    rec = Recorder()
    state.register_plugin(rec.NAME, rec)

    def _is_read_only(addr) -> bool:
        if not addr.concrete:
            return False
        a = state.solver.eval(addr)
        return any(base <= a < base + size for base, size in read_only_ranges)

    def before_read(state):
        addr = state.inspect.mem_read_address
        length = state.inspect.mem_read_length or 1
        if state.solver.symbolic(addr) and not _is_read_only(addr):
            state.inspect.mem_read_expr = _fresh_read_var(state, length * 8)

    def after_read(state):
        # Record into *this* state's recorder: inspect breakpoints are
        # copied verbatim to forked states, so the closure must resolve the
        # per-state plugin rather than use the instance captured at install
        # time (which would accumulate every path's ops on the initial
        # state's recorder and leave each fork's own list empty).
        r = state.vmspec_recorder
        addr = state.inspect.mem_read_address
        value = state.inspect.mem_read_expr
        length = state.inspect.mem_read_length or 1
        r.mem_ops.append(MemAccess("read", addr, value, length))

    def after_write(state):
        r = state.vmspec_recorder
        addr = state.inspect.mem_write_address
        value = state.inspect.mem_write_expr
        length = getattr(value, "size", lambda: 0)()
        length = length // 8 if length else 1
        r.mem_ops.append(MemAccess("write", addr, value, length))

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=before_read)
    state.inspect.b("mem_read", when=angr.BP_AFTER, action=after_read)
    state.inspect.b("mem_write", when=angr.BP_AFTER, action=after_write)
    return rec
