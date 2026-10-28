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


def analyze_handler(
    project: angr.Project,
    handler: Handler,
    vm_state: VMState,
    *,
    max_steps: int = 100_000,
) -> StateNode | None:
    """Symbolically execute `handler` and return its state tree.

    The initial state is created at ``handler.entry`` with the
    no-concretization memory model installed. Exploration runs until every
    state either reaches ``handler.end`` (the terminator) or exceeds
    ``max_steps`` (truncated paths are kept as leaves).

    ``vm_state`` is currently informational (it describes the VM registers and
    regions); the handler boundaries drive the exploration.
    """
    init = project.factory.blank_state(addr=handler.entry)
    recorder = install(init)

    def on_call(state):
        target = state.inspect.function_address
        recorder.calls.append(Call(state.addr, target))

    init.inspect.b("call", when=angr.BP_BEFORE, action=on_call)

    simgr = project.factory.simulation_manager(init)

    def reached_end(s):
        return s.addr == handler.end

    simgr.explore(find=reached_end, num_find=0)

    # Anything still active past the budget becomes a truncated leaf.
    truncated = simgr.stashes.setdefault("truncated", [])
    for s in list(simgr.active):
        if s.history.depth > max_steps:
            truncated.append(s)
            simgr.active.remove(s)

    leaves = simgr.deadended + simgr.found + truncated
    return _build_tree(leaves)


def _build_tree(leaves: list[angr.SimState]) -> StateNode | None:
    """Reconstruct a :class:`StateNode` tree from leaf states' histories.

    Common prefixes of the execution lineages are shared, so branching points
    become interior nodes and each leaf keeps its accumulated memory ops and
    calls. Branch conditions are taken from ``history.jump_guard``.
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
                    addr=h.addr,
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
