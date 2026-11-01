"""Segmented, non-concretizing memory for handler analysis.

Writes are cached per path. A possible alias invalidates older cached values;
an unambiguous read reuses the stored bytes. Only declared read-only memory
may be read from the underlying image.
"""
from __future__ import annotations

from dataclasses import dataclass

import angr
import claripy

from .model import Call, MemAccess, RegionKind, VMState


@dataclass(frozen=True)
class _Write:
    addr: object
    value: object
    size: int
    endness: str
    region: int | None


class Recorder(angr.SimStatePlugin):
    """Memory cache and event log belonging to one execution path."""

    NAME = "vmspec_recorder"

    def __init__(self, regions=(), read_only_ranges=()):
        super().__init__()
        self.regions = tuple(regions)
        self.read_only_ranges = tuple(read_only_ranges)
        self.mem_ops: list[MemAccess] = []
        self.calls: list[Call] = []
        self.recent_writes: list[_Write] = []

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        c = Recorder(self.regions, self.read_only_ranges)
        c.mem_ops = list(self.mem_ops)
        c.calls = list(self.calls)
        c.recent_writes = list(self.recent_writes)
        return c

    def merge(self, others, merge_conditions, common_ancestor=None):
        return False

    def widen(self, others):
        return False

    def record(self, op):
        if isinstance(op, MemAccess):
            self.mem_ops.append(op)
        else:
            self.calls.append(op)
        self.state.history.add_event("vmspec", operation=op)

    def _inside(self, addr, size, base, length):
        if base is None or length is None or size > length or length <= 0:
            return False
        if base < 0 or base + length > 1 << self.state.arch.bits:
            return False
        return not self.state.solver.satisfiable(extra_constraints=[
            claripy.Or(addr < base, addr > base + length - size)
        ])

    def region(self, addr, size):
        matches = [
            i for i, region in enumerate(self.regions)
            if self._inside(addr, size, region.base, region.size)
        ]
        return matches[0] if len(matches) == 1 else None

    def read_only(self, addr, size):
        ranges = self.read_only_ranges + tuple(
            (r.base, r.size) for r in self.regions if r.kind == RegionKind.READONLY
        )
        return any(self._inside(addr, size, base, length) for base, length in ranges)

    def load(self, addr, size, endness):
        solver = self.state.solver
        for write in reversed(self.recent_writes):
            if size > write.size:
                continue
            delta = claripy.simplify(addr - write.addr)
            offsets = solver.eval_upto(delta, 2)
            if len(offsets) != 1 or offsets[0] + size > write.size:
                continue
            offset = offsets[0]
            raw = write.value.reversed if write.endness == "Iend_LE" else write.value
            raw = raw.get_bytes(offset, size)
            return (raw.reversed if endness == "Iend_LE" else raw), True
        if self.read_only(addr, size):
            addresses = solver.eval_upto(addr, 2)
            if len(addresses) == 1:
                return self.state.memory.load(
                    addresses[0], size, endness=endness, inspect=False
                ), True
        return claripy.BVS("vmspec_mem_read", size * 8), False

    def _disjoint_regions(self, left, right):
        if left is None or right is None or left == right:
            return False
        a, b = self.regions[left], self.regions[right]
        return a.base + a.size <= b.base or b.base + b.size <= a.base

    def store(self, addr, value, size, endness):
        region = self.region(addr, size)
        # Modular subtraction also detects overlap at the address-space boundary.
        self.recent_writes = [
            old for old in self.recent_writes
            if self._disjoint_regions(region, old.region) or not self.state.solver.satisfiable(extra_constraints=[
                claripy.Or(addr - old.addr < old.size, old.addr - addr < size)
            ])
        ]
        self.recent_writes.append(_Write(addr, value, size, endness, region))


def _length(state, value):
    if isinstance(value, int):
        length = value
    else:
        choices = state.solver.eval_upto(value, 2)
        if len(choices) != 1:
            raise ValueError("symbolic memory access size is not supported")
        length = choices[0]
    if length <= 0:
        raise ValueError("memory access size must be positive")
    return length


def _condition(state, cond):
    if cond is None or state.solver.is_true(cond):
        return True
    if state.solver.is_false(cond):
        return False
    raise ValueError("conditional memory access requires a separate execution path")


def install(state, read_only_ranges=(), *, vm_state: VMState | None = None) -> Recorder:
    """Install path-local segmented memory, without choosing pointer values."""
    rec = Recorder(vm_state.regions if vm_state else (), read_only_ranges)
    state.register_plugin(rec.NAME, rec)
    # The recorder handles symbolic writes; angr must not pick their addresses.
    state.options.add(angr.options.AVOID_MULTIVALUED_WRITES)

    def before_read(s):
        size = _length(s, s.inspect.mem_read_length)
        if not _condition(s, s.inspect.mem_read_condition):
            s.inspect.mem_read_expr = claripy.BVV(0, size * 8)
            return
        addr = s.inspect.mem_read_address
        if isinstance(addr, int):
            addr = claripy.BVV(addr, s.arch.bits)
        endness = s.inspect.mem_read_endness or s.memory.endness
        value, forwarded = s.vmspec_recorder.load(addr, size, endness)
        s.inspect.mem_read_expr = value
        s.vmspec_recorder.record(MemAccess("read", addr, value, size, forwarded, endness))

    def before_write(s):
        if not _condition(s, s.inspect.mem_write_condition):
            return
        value = s.inspect.mem_write_expr
        size = _length(s, s.inspect.mem_write_length if s.inspect.mem_write_length is not None else value.size() // 8)
        addr = s.inspect.mem_write_address
        if isinstance(addr, int):
            addr = claripy.BVV(addr, s.arch.bits)
        if size * 8 > value.size():
            raise ValueError("memory write is wider than its value")
        value = value[size * 8 - 1:0]
        r = s.vmspec_recorder
        if r.read_only(addr, size):
            raise ValueError("write to declared read-only memory")
        r.store(addr, value, size, s.inspect.mem_write_endness or s.memory.endness)
        r.record(MemAccess("write", addr, value, size, endness=s.inspect.mem_write_endness or s.memory.endness))

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=before_read)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=before_write)
    return rec
