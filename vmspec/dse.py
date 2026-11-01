"""DSE harness for VM handlers (angr).

Symbolically execute all paths of a single VM handler, recording memory
operations, function calls, and branch conditions, then build a state tree
(paper §4.2 / §4.3).

The memory model from :mod:`vmspec.memory` is installed on the initial state;
angr copies the inspect breakpoints and the recorder plugin to every forked
state, so each path accumulates its own memory ops and calls.
"""

from __future__ import annotations

import angr
import claripy

from .memory import install
from .model import Call, Handler, StateNode, VMState

def analyze_handler(
    project: angr.Project,
    handler: Handler,
    vm_state: VMState,
    *,
    max_steps: int = 100_000,
) -> StateNode | None:
    """Explore a handler using configured boundaries and segmented memory.

    Incomplete paths are rejected; they must never become apparently complete
    instruction semantics.
    """
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if project.arch.bits != 32 or project.arch.memory_endness != "Iend_LE":
        raise ValueError("the current SLEIGH backend requires a 32-bit little-endian target")
    init = project.factory.blank_state(addr=handler.entry)
    initial_registers = {}
    for name in [vm_state.vpc, vm_state.vsp, *vm_state.context]:
        if name in project.arch.registers:
            _, width = project.arch.registers[name]
            if width != 4:
                raise ValueError(f"VM register {name} must be 32 bits")
            initial_registers[name] = claripy.BVS(name, width * 8, explicit_name=True)
            setattr(init.regs, name, initial_registers[name])
    install(init, vm_state=vm_state)

    def on_call(state):
        # Resolve the per-state recorder from the state itself: inspect
        # breakpoints are copied to forked states, so the original
        # instance returned by :func:`install` only sees the initial state.
        target = state.inspect.function_address
        state.vmspec_recorder.record(Call(state.addr, target))
        raise NotImplementedError("native calls require specialized semantics")

    init.inspect.b("call", when=angr.BP_BEFORE, action=on_call)

    simgr = project.factory.simulation_manager(init)

    def reached_end(s: angr.SimState) -> bool:
        try:
            addr = s.addr
        except angr.SimValueError:
            return False
        return addr == handler.end or any(
            base <= addr < base + size for base, size in vm_state.dispatcher_ranges
        )

    # Step-by-step exploration bounded by the budget.  ``explore`` alone
    # keeps stepping states past the terminator (they jump into the
    # dispatcher and then into unconstrained native code), so every
    # iteration moves the states parked in the dispatcher zone out of
    # ``active`` into ``found`` before they can fall further into the blob.
    for _ in range(max_steps):
        simgr.move("active", "found", reached_end)
        if not simgr.active:
            break
        simgr.step(extra_stop_points={handler.end, *(base for base, _ in vm_state.dispatcher_ranges)})
        simgr.move("active", "found", reached_end)
        if not simgr.active:
            break

    if simgr.active or simgr.errored or simgr.unconstrained or simgr.deadended:
        raise RuntimeError(
            f"handler 0x{handler.entry:X}: incomplete DSE "
            f"(active={len(simgr.active)}, errors={len(simgr.errored)}, "
            f"unconstrained={len(simgr.unconstrained)}, deadended={len(simgr.deadended)})"
        )
    for leaf in simgr.found:
        for name, initial in initial_registers.items():
            if not leaf.solver.is_true(getattr(leaf.regs, name) == initial):
                raise NotImplementedError(f"VM register update {name} requires register-effect lowering")
    return _build_tree(simgr.found, entry=handler.entry)


def _build_tree(leaves: list[angr.SimState], *, entry: int) -> StateNode | None:
    """Build a prefix tree of ordered events and outgoing branch guards.

    A history's guard selects the state *after* its events. Event identities
    survive angr forks, so loads before a branch are shared and precede the
    guard that uses their result.
    """
    if not leaves:
        return None
    root = StateNode(addr=entry)
    nodes = {}
    for leaf in leaves:
        lineage = []
        h = leaf.history
        while h is not None:
            lineage.append(h)
            h = h.parent
        prev = root
        for h in reversed(lineage):
            for event in h.recent_events:
                if event.type != "vmspec":
                    continue
                key = (id(prev), "event", event.id)
                node = nodes.get(key)
                if node is None:
                    op = event.objects["operation"]
                    node = StateNode(addr=event.ins_addr or h.addr or entry)
                    if isinstance(op, Call):
                        node.calls.append(op)
                    else:
                        node.mem_ops.append(op)
                    prev.successors.append(node)
                    nodes[key] = node
                prev = node
            guard = h.jump_guard
            if guard is None:
                continue
            target = h.jump_target
            key = (id(prev), "edge", id(guard), id(target))
            node = nodes.get(key)
            if node is None:
                addr = target.args[0] if getattr(target, "op", None) == "BVV" else h.addr
                node = StateNode(addr=addr or entry, cond=guard)
                prev.successors.append(node)
                nodes[key] = node
            prev = node
    return root
