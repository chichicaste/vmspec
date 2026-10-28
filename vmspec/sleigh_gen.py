"""SLEIGH processor-spec generation (VMSpec pipeline step 5).

Turns the merged state graph into a minimal ``.slaspec`` document:

* a header with ``define space`` declarations plus one ``define register``
  per VM state region (the virtual program counter, the virtual stack
  pointer and the context variables are included);
* one instruction constructor per opcode handler: the opcode bit-pattern
  as the constructor pattern and the P-Code semantics translated from the
  state-graph ops reachable from the handler entry.

Emitted P-Code: ``LOAD`` / ``STORE`` for symbolic memory reads and
writes, ``CALL`` for recorded calls, ``COPY`` / ``INT_ADD`` / ``INT_SUB``
(and other named arithmetic ops) for explicit ops, and ``CBRANCH`` for
guarded control transfers.  Opaque symbolic values are rendered as
numbered placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vmspec.model import Call, GraphNode, Handler, MemAccess, RegionKind, VMState

__all__ = ["generate_sleigh"]

# The address space in which each region kind lives.
_SPACE_BY_KIND: dict[RegionKind, str] = {
    RegionKind.CODE: "ram",
    RegionKind.GLOBAL: "ram",
    RegionKind.STACK: "context",
    RegionKind.STATE: "context",
    RegionKind.CONTEXT: "context",
}

# Explicit arithmetic ops (and their P-Code operand counts) recognised in a
# node's ``ops`` list: either as bare names (placeholder operands) or as
# ``(name, *operands)`` tuples (operands rendered as expressions).
_PCODE_ARITY: dict[str, int] = {
    "COPY": 2,
    "INT_ADD": 3,
    "INT_SUB": 3,
    "INT_MUL": 3,
    "INT_DIV": 3,
    "INT_AND": 3,
    "INT_OR": 3,
    "INT_XOR": 3,
    "INT_ZEXT": 2,
    "INT_SEXT": 2,
}


@dataclass
class _Render:
    """Symbolic-placeholder numbering state for a single constructor."""

    reg_names: frozenset[str] = frozenset()
    _tmp: int = field(default=1, repr=False)
    _sym: int = field(default=1, repr=False)
    vars: dict[int, str] = field(default_factory=dict, repr=False)

    def fresh_tmp(self) -> str:
        """A fresh SLEIGH temporary (``#n``)."""
        name = f"#{self._tmp}"
        self._tmp += 1
        return name

    def fresh_sym(self) -> str:
        """A fresh unnamed symbol placeholder (``SYNn``)."""
        name = f"SYN{self._sym}"
        self._sym += 1
        return name

    def var_name(self, obj: Any) -> str:
        """Stable name bound to a produced symbolic value (read variable,
        call return, ...)."""
        key = id(obj)
        name = self.vars.get(key)
        if name is None:
            name = self.fresh_tmp()
            self.vars[key] = name
        return name

    def render(self, expr: Any) -> str:
        """Render an opaque expression as a SLEIGH operand placeholder."""
        if expr is None:
            return "0x0"
        if isinstance(expr, bool):
            return "0x1" if expr else "0x0"
        if isinstance(expr, int):
            return f"0x{expr:X}"
        if isinstance(expr, bytes):
            return f"0x{expr.hex().upper()}"
        if isinstance(expr, (list, tuple)):
            if not expr:
                return "0x0"
            return "[" + ",".join(self.render(e) for e in expr) + "]"
        if isinstance(expr, str):
            # Names of defined registers reference the register; anything
            # else is assumed to be a pre-rendered SLEIGH expression.
            return expr
        bound = self.vars.get(id(expr))
        if bound is not None:
            return bound
        sym = self.fresh_sym()
        self.vars[id(expr)] = sym
        return sym


def _label(raw: str) -> str:
    """Sanitise *raw* into a valid SLEIGH label."""
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in raw)
    if not out or out[0].isdigit():
        out = "op_" + out
    return out or "op"


def _node_label(node_id: int) -> str:
    return f"node_{node_id}"


def _body_nodes(graph: GraphNode, entry: int) -> list[GraphNode]:
    """Ordered state-graph nodes covering one handler body.

    Starts at the node whose ``addr`` matches the handler entry (falling
    back to the graph root) and walks successors in order, visiting every
    node at most once (back-edges therefore terminate the walk).
    """
    registry: dict[int, GraphNode] = getattr(graph, "_nodes", None) or {
        graph.id: graph
    }
    start = next((n for n in registry.values() if n.addr == entry), graph)
    body: list[GraphNode] = []
    seen: set[int] = set()
    stack: list[int] = [start.id]
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        node = registry.get(nid)
        if node is None:
            continue
        body.append(node)
        for obj, tid in reversed(node.successors):
            if isinstance(obj, GraphNode):
                registry.setdefault(obj.id, obj)
                stack.append(obj.id)
            else:
                stack.append(tid)
    return body


def _emit_ops(node: GraphNode, r: _Render, out: list[str]) -> None:
    """Translate a graph node's ops into P-Code lines."""
    for op in node.ops:
        if isinstance(op, MemAccess):
            if op.kind == "read":
                dest = r.var_name(op.value)
                out.append(f"LOAD:{op.size} {dest},{r.render(op.addr)};")
            else:
                out.append(
                    f"STORE:{op.size} {r.render(op.addr)},{r.render(op.value)};"
                )
        elif isinstance(op, Call):
            out.append(f"CALL {r.fresh_tmp()},{r.render(op.target)};")
        elif isinstance(op, str) and op in _PCODE_ARITY:
            operands = ",".join(
                r.fresh_sym() for _ in range(_PCODE_ARITY[op])
            )
            out.append(f"{op} {operands};")
        elif (
            isinstance(op, (list, tuple))
            and op
            and isinstance(op[0], str)
            and op[0] in _PCODE_ARITY
        ):
            operands = ",".join(r.render(x) for x in op[1:])
            out.append(f"{op[0]} {operands};")
        else:
            out.append(f"# untranslatable op: {op!r}")


def _emit_control(node: GraphNode, r: _Render, out: list[str]) -> None:
    """Emit the control transfer(s) of a graph node."""
    if not node.successors:
        return
    if len(node.successors) == 1 and node.successors[0][0] is None:
        return  # plain fall-through, nothing to emit
    for cond, tid in node.successors:
        cond_text = r.render(cond) if cond is not None else r.fresh_sym()
        out.append(f"CBRANCH {cond_text},{_node_label(tid)};")


def _opcode_pattern(opcode: int) -> str:
    """Least-significant opcode bytes as a comma-separated SLEIGH pattern."""
    width = max(1, (opcode.bit_length() + 7) // 8)
    return ",".join(
        f"0x{(opcode >> (8 * i)) & 0xFF:02X}" for i in range(width - 1, -1, -1)
    )


def generate_sleigh(
    graph: GraphNode, vm_state: VMState, handlers: list[Handler]
) -> str:
    """Generate a minimal SLEIGH ``.slaspec`` for the VM described by
    *vm_state*, with one per-handler constructor derived from *graph*."""
    # Registry of usable register names (for resolving symbolic references).
    reg_names: set[str] = {vm_state.vpc}
    if vm_state.vsp is not None:
        reg_names.add(vm_state.vsp)
    for name in vm_state.context:
        reg_names.add(name)
    for region in vm_state.regions:
        reg_names.add(region.name)

    lines: list[str] = []
    lines.append("// VMSpec auto-generated processor specification (.slaspec)")
    lines.append("// Pipeline: DSE -> state tree -> state graph -> SLEIGH")
    lines.append("// Reference: arXiv:2610.29566")
    lines.append("version 2.0")
    lines.append("")
    lines.append("#define int 1 0 -1")
    lines.append("")

    # Address spaces.
    lines.append('define space ram ( "ram", 0, 4 )')
    lines.append('define space context ( "context", 0, 4 )')
    lines.append("")

    # Registers: VPC / VSP, state regions and context variables.
    def _define_register(name: str, space: str) -> None:
        if name.lower() in seen_regs:
            return
        seen_regs.add(name.lower())
        display = _label(name).upper()
        lines.append(f'define register "{name}" ( "{display}" ) belongsTo( {space} )')
        reg_names.add(name)

    seen_regs: set[str] = set()
    _define_register(vm_state.vpc, "context")
    if vm_state.vsp is not None:
        _define_register(vm_state.vsp, "context")
    for region in vm_state.regions:
        _define_register(region.name, _SPACE_BY_KIND[region.kind])
    for name in vm_state.context:
        _define_register(name, "context")
    lines.append("")

    # Handler constructors.
    r = _Render(reg_names=frozenset(reg_names))
    used_labels: set[str] = set()
    for handler in handlers:
        body = _body_nodes(graph, handler.entry)
        base = _label(handler.mnemonic or f"op_{handler.opcode:X}")
        name, k = base, 1
        while name in used_labels:
            name = f"{base}_{k}"
            k += 1
        used_labels.add(name)
        lines.append(
            f"// handler opcode=0x{handler.opcode:X} "
            f"entry=0x{handler.entry:X} end=0x{handler.end:X}"
        )
        lines.append(f":{name} {_opcode_pattern(handler.opcode)}: {{")
        use_labels = len(body) > 1 or any(n.successors for n in body)
        for node in body:
            if use_labels:
                lines.append(f"  {_node_label(node.id)}:")
            node_lines: list[str] = []
            _emit_ops(node, r, node_lines)
            _emit_control(node, r, node_lines)
            for line in node_lines:
                lines.append(f"  {line}")
        lines.append("}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"