"""State-tree to state-graph transformation (VMSpec pipeline step 4).

The DSE engine produces one state tree per handler.  This module collapses
such a tree into a state graph in two passes:

1. **Dead-memory elimination** (def-use analysis over the tree).

   * A *write* is dead when, on *every* continuation path, the next access
     to the same address is another write -- the value is overwritten
     before it can ever be read.
   * A *read* is dead when the fresh variable it produces is never used by
     any later memory access, call target or branch guard on any
     continuation path.  Under the VMSpec memory model every read yields a
     fresh variable, so liveness is a direct ref-use question.

2. **Node merge.**  Nodes that share the same ``addr``, the same (in-order)
   memory operations and the same successor set are fused into a single
   :class:`vmspec.model.GraphNode`.

The returned graph is rooted at the DSE root and every node id resolves
through a mapping attached to the root as the ``_nodes`` attribute, so the
SLEIGH generator can follow successor references.  Only the standard
library is used.
"""

from __future__ import annotations

import itertools
from typing import Any

from vmspec.model import Call, GraphNode, MemAccess, StateNode

__all__ = ["build_state_graph"]

_READ = "read"
_WRITE = "write"

# Possible "next access to the address" outcomes aggregated over all
# continuation paths below a program point.
_NO_ACCESS = frozenset({"none"})
_NEXT_READ = frozenset({"read"})
_NEXT_WRITE = frozenset({"write"})


def _same(a: Any, b: Any) -> bool:
    """Safe equality: identity first, then ``==`` when it is defined."""
    if a is b:
        return True
    try:
        return bool(a == b)
    except Exception:
        return False


def _sig(x: Any) -> tuple:
    """Hash-stable signature for an opaque expression.

    Hashable objects are bucketed by ``(hash, type)``; unhashable ones fall
    back to their identity.  Signatures are only used for bucketing, so
    collisions are resolved with a full ``==`` comparison at the point of
    use.
    """
    if x is None:
        return ("none",)
    try:
        return ("hash", hash(x), type(x).__name__)
    except TypeError:
        return ("id", id(x), type(x).__name__)


def _expr_uses_direct(expr: Any, var: Any) -> bool:
    """Return ``True`` when *expr* directly references the symbolic *var*.

    Direct references covered: identity/equality, an iterable
    ``free_vars`` attribute (the convention used by symbolic backends to
    expose the variables an expression depends on), and plain containers,
    which the caller recurses into.
    """
    if expr is None or var is None:
        return False
    if expr is var:
        return True
    try:
        if expr == var:
            return True
    except Exception:
        pass
    free = getattr(expr, "free_vars", None)
    if free is None:
        return False
    if callable(free):
        try:
            free = free()
        except Exception:
            return False
    try:
        members = list(free)
    except TypeError:
        return _same(free, var)
    for member in members:
        if _same(member, var):
            return True
    return False


def _postorder(root: StateNode) -> list[StateNode]:
    """Nodes of the tree in post-order (children before their parent).

    Works on DAGs as well as trees: each node appears exactly once and its
    successors are processed before it.
    """
    order: list[StateNode] = []
    seen: set[int] = set()
    stack: list[tuple[StateNode, bool]] = [(root, False)]
    while stack:
        node, ready = stack.pop()
        if ready:
            order.append(node)
            continue
        if id(node) in seen:
            continue
        seen.add(id(node))
        stack.append((node, True))
        for succ in reversed(node.successors):
            stack.append((succ, False))
    return order


def build_state_graph(root: StateNode) -> GraphNode:
    """Collapse the DSE state tree rooted at *root* into a state graph.

    Runs dead-memory elimination (see the module docstring) and then merges
    equivalent nodes.  Returns the :class:`GraphNode` matching *root*; the
    full ``id -> GraphNode`` mapping is attached to it as ``_nodes``.
    """
    order = _postorder(root)

    # ------------------------------------------------------------------ #
    # 1a. Collect the fresh variables produced by the tree's reads.
    # ------------------------------------------------------------------ #
    all_vars: list[Any] = []
    var_index: dict[tuple, int] = {}
    for node in order:
        for op in node.mem_ops:
            if op.kind == _READ:
                sig = _sig(op.value)
                if sig not in var_index:
                    var_index[sig] = len(all_vars)
                    all_vars.append(op.value)

    def _expr_var_indices(expr: Any) -> set[int]:
        """Indices (into *all_vars*) of the variables referenced by *expr*."""
        if not all_vars:
            return set()
        found: set[int] = set()
        stack: list[Any] = [expr]
        seen: set[int] = set()
        while stack:
            item = stack.pop()
            if item is None or id(item) in seen:
                continue
            seen.add(id(item))
            for idx, var in enumerate(all_vars):
                if idx in found:
                    continue
                if _expr_uses_direct(item, var):
                    found.add(idx)
            if isinstance(item, (list, tuple, set, frozenset)):
                stack.extend(item)
        return found

    # ------------------------------------------------------------------ #
    # 1b. Cluster structurally-equal addresses so that per-address facts
    #     can be kept in plain dicts (addresses are opaque and may be
    #     unhashable).
    # ------------------------------------------------------------------ #
    clusters: list[Any] = []
    addr_cluster: dict[int, int] = {}
    for node in order:
        for op in node.mem_ops:
            addr = op.addr
            aid = id(addr)
            if aid in addr_cluster:
                continue
            idx = len(clusters)
            for j, rep in enumerate(clusters):
                if _same(rep, addr):
                    idx = j
                    break
            else:
                clusters.append(addr)
            addr_cluster[aid] = idx

    # ------------------------------------------------------------------ #
    # 1c. Backward def-use pass, one state node at a time.
    #
    #     *facts* tracks, per address, which kinds of "next access" are
    #     possible over the continuation paths below the current pointer;
    #     a write is dead exactly when only overwrites are possible.
    #     *live* tracks which produced variables are used strictly after
    #     the current position; a read is dead when its own variable is
    #     not used there.
    # ------------------------------------------------------------------ #
    dead_ops: dict[int, set[int]] = {}
    use_sets: dict[int, set[int]] = {}
    fact_sets: dict[int, dict[int, frozenset]] = {}

    for node in order:
        facts: dict[int, frozenset] = {}
        for succ in node.successors:
            for ci, fc in fact_sets[id(succ)].items():
                facts[ci] = facts.get(ci, frozenset()) | fc

        live: set[int] = set()
        if node.cond is not None:
            live |= _expr_var_indices(node.cond)
        for call in node.calls:
            live |= _expr_var_indices(call.target)
        for succ in node.successors:
            live |= use_sets[id(succ)]

        node_dead: set[int] = set()
        for i in range(len(node.mem_ops) - 1, -1, -1):
            op = node.mem_ops[i]
            ci = addr_cluster[id(op.addr)]
            if op.kind == _WRITE:
                if facts.get(ci, _NO_ACCESS) == _NEXT_WRITE:
                    node_dead.add(i)
                facts[ci] = _NEXT_WRITE
            else:
                facts[ci] = _NEXT_READ
                if var_index[_sig(op.value)] not in live:
                    node_dead.add(i)
            live |= _expr_var_indices(op.addr)
            if op.kind == _WRITE:
                live |= _expr_var_indices(op.value)

        dead_ops[id(node)] = node_dead
        use_sets[id(node)] = live
        fact_sets[id(node)] = facts

    # ------------------------------------------------------------------ #
    # 2. Merge equivalent nodes (same addr, in-order ops and successors).
    # ------------------------------------------------------------------ #
    counter = itertools.count()
    cache: dict[tuple, GraphNode] = {}
    graph_of: dict[int, GraphNode] = {}

    def _op_sig(op: Any) -> tuple:
        if isinstance(op, MemAccess):
            return ("mem", op.kind, op.size, _sig(op.addr), _sig(op.value))
        if isinstance(op, Call):
            return ("call", op.site, _sig(op.target))
        return ("op", _sig(op), type(op).__name__)

    for node in order:
        succ_graphs = [graph_of[id(s)] for s in node.successors]
        clean = [
            op for i, op in enumerate(node.mem_ops) if i not in dead_ops[id(node)]
        ]
        ops = clean + list(node.calls)
        key = (
            node.addr,
            frozenset(g.id for g in succ_graphs),
            tuple(_op_sig(op) for op in clean),
            tuple(_op_sig(op) for op in node.calls),
        )
        hit = cache.get(key)
        if hit is not None and hit.addr == node.addr and hit.ops == ops:
            graph_of[id(node)] = hit
            continue
        graph = GraphNode(
            id=next(counter),
            addr=node.addr,
            ops=list(ops),
            successors=[(s.cond, g.id) for s, g in zip(node.successors, succ_graphs)],
        )
        cache[key] = graph
        graph_of[id(node)] = graph

    root_graph = graph_of[id(root)]
    # id -> GraphNode map, needed by the SLEIGH generator to resolve
    # successor references.
    root_graph._nodes = {ng.id: ng for ng in graph_of.values()}  # type: ignore[attr-defined]
    return root_graph