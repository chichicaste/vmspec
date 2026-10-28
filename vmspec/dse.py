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

from .memory import install
from .model import Call, Handler, StateNode, VMState

# Dispatcher zone inside the blob.  ``DISPATCHER`` in :mod:`tools.gen_config`
# (0x1AE1198) is the main dispatcher entry, but some handlers terminate by
# jumping into variant entries (e.g. 0x1AE1193) that share the same block.
# The whole block spans [0x1AE1193, 0x1AE11B4); the next handler
# ("shrd") starts at 0x1AE11B5.  Treating the entire zone as "end" keeps any
# state out of the dispatcher, whose tail ``jmp`` targets a symbolically
# indexed table and would explode the path count (one indirect jump per
# state, each expanded into 256 solutions).
DISPATCHER_RANGE: tuple[int, int] = (0x1AE1193, 0x1AE11B4)


def analyze_handler(
    project: angr.Project,
    handler: Handler,
    vm_state: VMState,
    *,
    max_steps: int = 100_000,
) -> StateNode | None:
    """Symbolically execute `handler` and return its state tree.

    The initial state is created at ``handler.entry`` with the
    no-concretization memory model installed. Exploration is bounded by
    ``max_steps``: since every handler ends with an absolute ``jmp`` into
    the in-blob dispatcher, one step per iteration is followed by moving
    the states parked in the dispatcher zone (``DISPATCHER_RANGE``) into the
    ``found`` stash; exploration stops when no state is left active or the
    budget runs out (remaining paths are kept as truncated leaves).

    ``handler.end`` (0x1AE1198) is the canonical dispatcher entry recorded
    in the config, but some handlers jump into a different entry of the
    same dispatcher block; the range check accepts the whole zone.

    ``vm_state`` is currently informational (it describes the VM registers and
    regions); the handler boundaries drive the exploration.
    """
    init = project.factory.blank_state(addr=handler.entry)
    install(init)

    def on_call(state):
        # Resolve the per-state recorder from the state itself: inspect
        # breakpoints are copied to forked states, so the original
        # instance returned by :func:`install` only sees the initial state.
        target = state.inspect.function_address
        state.vmspec_recorder.calls.append(Call(state.addr, target))

    init.inspect.b("call", when=angr.BP_BEFORE, action=on_call)

    simgr = project.factory.simulation_manager(init)

    def reached_end(s: angr.SimState) -> bool:
        """True when `s` has reached the dispatcher zone.

        The dispatcher zone spans one straight-line block, so an exact
        match on ``handler.end`` would miss states that enter the block
        through a different instruction (e.g. the variant at 0x1AE1193)
        and let them execute the dispatcher's symbolic table jump.  A
        state whose IP is symbolic is not considered at the end either.
        """
        try:
            addr = s.addr
        except angr.SimValueError:
            return False
        return DISPATCHER_RANGE[0] <= addr < DISPATCHER_RANGE[1]

    # Step-by-step exploration bounded by the budget.  ``explore`` alone
    # keeps stepping states past the terminator (they jump into the
    # dispatcher and then into unconstrained native code), so every
    # iteration moves the states parked in the dispatcher zone out of
    # ``active`` into ``found`` before they can fall further into the blob.
    for _ in range(max_steps):
        if not simgr.active:
            break
        simgr.step()
        simgr.move("active", "found", reached_end)
        if not simgr.active:
            break

    # Whatever is still active at the budget becomes a truncated leaf.
    truncated = simgr.stashes.setdefault("truncated", [])
    truncated.extend(simgr.active)
    simgr.active.clear()

    leaves = simgr.deadended + simgr.found + truncated
    return _build_tree(leaves, entry=handler.entry)


def _build_tree(leaves: list[angr.SimState], *, entry: int) -> StateNode | None:
    """Reconstruct a :class:`StateNode` tree from leaf states' histories.

    Common prefixes of the execution lineages are shared, so branching points
    become interior nodes and each leaf keeps its accumulated memory ops and
    calls. Branch conditions are taken from ``history.jump_guard``.

    Node addresses come from ``history.addr`` (start of the last basic block
    executed by that step). The lineage's first history is the initial state's
    history, which has not executed any block yet and therefore reports
    ``None``; the root node is given ``entry`` (the initial instruction
    pointer) instead.
    """
    if not leaves:
        return None

    nodes: dict[int, StateNode] = {}
    root: StateNode | None = None

    for leaf in leaves:
        lineage: list[angr.SimStateHistory] = []
        h = leaf.history
        while h is not None:
            lineage.append(h)
            h = h.parent
        lineage.reverse()  # root -> leaf

        rec = getattr(leaf, "vmspec_recorder", None)
        leaf_ops = list(rec.mem_ops) if rec else []
        leaf_calls = list(rec.calls) if rec else []

        prev: StateNode | None = None
        for depth, h in enumerate(lineage):
            is_leaf = depth == len(lineage) - 1
            key = id(h)
            node = nodes.get(key)
            if node is None:
                node = StateNode(
                    addr=h.addr if h.addr is not None else entry,
                    mem_ops=leaf_ops if is_leaf else [],
                    calls=leaf_calls if is_leaf else [],
                )
                if prev is not None:
                    node.cond = getattr(h, "jump_guard", None)
                    prev.successors.append(node)
                else:
                    root = node
                nodes[key] = node
            prev = node

    return root
