"""Preserve handler effects while removing unused read definitions.

Stores are retained: equality of two pointer expressions alone cannot prove
that intervening accesses do not alias. Equivalent nodes merge only when
their ordered operations and guarded successor edges agree.
"""
from __future__ import annotations

from .model import Call, GraphNode, MemAccess, StateNode


def _key(value):
    if value is None or isinstance(value, (str, int, bool)):
        return (type(value).__name__, value)
    if isinstance(value, (tuple, list)):
        return tuple(_key(item) for item in value)
    # Claripy interns ASTs; identity avoids symbolic Python equality.
    return (type(value).__name__, id(value))


def _references(expr):
    refs = set()
    pending = [expr]
    while pending:
        item = pending.pop()
        key = _key(item)
        if key in refs:
            continue
        refs.add(key)
        if hasattr(item, "args"):
            pending.extend(item.args)
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return refs


def _postorder(root):
    order, done, active = [], set(), set()
    stack = [(root, False)]
    while stack:
        node, ready = stack.pop()
        key = id(node)
        if ready:
            active.remove(key)
            done.add(key)
            order.append(node)
        elif key in active:
            raise ValueError("state tree contains a cycle")
        elif key not in done:
            active.add(key)
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(node.successors))
    return order


def build_state_graph(root: StateNode) -> GraphNode:
    """Eliminate unused loads and merge equal nodes, including edge guards."""
    graphs, uses, cache = {}, {}, {}
    for node in _postorder(root):
        live = set()
        for child in node.successors:
            live.update(uses[id(child)])
        for call in node.calls:
            live.update(_references(call.target))
        kept = []
        for op in reversed(node.mem_ops):
            if op.kind == "read":
                if op.forwarded or _key(op.value) not in live:
                    continue
                live.discard(_key(op.value))
            else:
                live.update(_references(op.value))
            live.update(_references(op.addr))
            kept.append(op)
        # Incoming conditions execute before this node's effects.
        live.update(_references(node.cond))
        uses[id(node)] = live
        ops = list(reversed(kept)) + list(node.calls)
        edges = [(child.cond, graphs[id(child)].id) for child in node.successors]
        signatures = tuple(
            ("mem", op.kind, op.size, op.endness, _key(op.addr), _key(op.value))
            if isinstance(op, MemAccess) else ("call", op.site, _key(op.target))
            for op in ops
        )
        key = (node.addr, signatures, tuple((_key(cond), nid) for cond, nid in edges))
        if key not in cache:
            cache[key] = GraphNode(len(cache), node.addr, ops, edges)
        graphs[id(node)] = cache[key]
    graph = graphs[id(root)]
    graph._nodes = {node.id: node for node in graphs.values()}
    return graph
