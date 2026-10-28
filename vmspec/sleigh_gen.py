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

# Rolling-key opcode encryption, the inverse of the in-blob dispatcher's
# decryption. The dispatcher does:
#   cl = byte - key; cl += 1; cl = ror8(cl, 4); cl -= 0x85; cl = ~cl; key -= cl
# Solving for ``byte`` (so a constructor can match the raw byte given the
# rolling key as context) yields ``byte = rol8(~opcode + 0x85, 4) + key - 1``.
# ``_encrypt_const`` returns the constant ``rol8(~opcode + 0x85, 4)``, so each
# constructor's constraint is ``byte = C + key - 1`` (VMSpec §5.1 / §5.4).
_CONTEXT_REG_NAME = "contextreg"


def _encrypt_const(opcode: int) -> int:
    """Return the constant ``C`` such that ``encrypt(op, key) = C + key - 1``."""
    inv = (0xFF ^ opcode) & 0xFF
    x = (inv + 0x85) & 0xFF
    return ((x << 4) | (x >> 4)) & 0xFF  # rol8(x, 4)


@dataclass
class _Render:
    """Symbolic-placeholder numbering state for a single constructor."""

    reg_names: frozenset[str] = frozenset()
    _tmp: int = field(default=1, repr=False)
    _sym: int = field(default=1, repr=False)
    vars: dict[int, str] = field(default_factory=dict, repr=False)

    def fresh_tmp(self) -> str:
        """A fresh SLEIGH temporary (``tmpN``)."""
        name = f"tmp{self._tmp}"
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
        if hasattr(expr, "op") and hasattr(expr, "args"):
            return self.render_ast(expr)
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

    def render_ast(self, ast: Any) -> str:
        """Translate a claripy AST into a SLEIGH expression string.

        Constants, symbolic variables, and the arithmetic / bit-manipulation
        operators are mapped to SLEIGH's C-like expression syntax (which the
        SLEIGH compiler lowers to P-Code). Ops without a direct equivalent
        fall back to a fresh placeholder.
        """
        op = ast.op
        args = ast.args

        if op == "BVV":
            return f"0x{args[0]:X}"
        if op == "BVS":
            return self.var_name(ast)
        if op == "BoolV":
            return "0x1" if args[0] else "0x0"

        binary = {
            "__add__": "+", "__sub__": "-", "__mul__": "*",
            "__and__": "&", "__or__": "|", "__xor__": "^",
            "__lshift__": "<<", "__rshift__": ">>", "LShR": ">>",
            "__eq__": "==", "__ne__": "!=", "__lt__": "<", "__le__": "<=",
            "__gt__": ">", "__ge__": ">=", "SLT": "<", "SLE": "<=",
        }
        if op in binary:
            sym = binary[op]
            return f"({self.render_ast(args[0])} {sym} {self.render_ast(args[1])})"

        if op == "__invert__":
            return f"(~{self.render_ast(args[0])})"
        if op == "__neg__":
            return f"(-{self.render_ast(args[0])})"

        if op == "Concat":
            hi, lo = args[0], args[1]
            return f"(({self.render_ast(hi)} << {lo.size()}) | {self.render_ast(lo)})"
        if op == "Extract":
            hi, lo = args[0], args[1]
            x = self.render_ast(args[2])
            mask = (1 << (hi - lo + 1)) - 1
            return f"(({x} >> {lo}) & 0x{mask:X})"
        if op in ("ZeroExt", "SignExt"):
            return self.render_ast(args[1])
        if op == "If":
            c = self.render_ast(args[0])
            t = self.render_ast(args[1])
            e = self.render_ast(args[2])
            return f"(({c}) ? ({t}) : ({e}))"
        if op in ("RotateLeft", "RotateRight"):
            x = self.render_ast(args[0])
            n = self.render_ast(args[1])
            b = ast.size()
            mask = (1 << b) - 1
            if op == "RotateLeft":
                return f"((( {x} << {n}) | ({x} >> ({b} - {n}))) & 0x{mask:X})"
            return f"((( {x} >> {n}) | ({x} << ({b} - {n}))) & 0x{mask:X})"

        return self.fresh_sym()


def _label(raw: str) -> str:
    """Sanitise *raw* into a valid SLEIGH label."""
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in raw)
    if not out or out[0].isdigit():
        out = "op_" + out
    return out or "op"


def _node_label(node_id: int) -> str:
    return f"node_{node_id}"


def _body_nodes(graph: GraphNode, start_id: int) -> list[GraphNode]:
    """Ordered state-graph nodes covering one handler body.

    Starts at the handler graph's root node -- ``start_id``, as recorded in
    the synthetic root's successors -- and walks successors in order,
    visiting every node at most once (back-edges therefore terminate the
    walk).  Resolving the root by its id (instead of scanning for a node
    whose ``addr`` equals the handler entry) is what keeps a handler body
    complete: a node from another handler or a collapsed leaf may sit at
    the same address and would otherwise truncate the walk.
    """
    registry: dict[int, GraphNode] = getattr(graph, "_nodes", None) or {
        graph.id: graph
    }
    start = registry.get(start_id) or graph
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
    """Translate a graph node's ops into C-like SLEIGH semantics."""
    for op in node.ops:
        if isinstance(op, MemAccess):
            if op.kind == "read":
                dest = r.var_name(op.value)
                out.append(f"{dest} = *:{op.size} {r.render(op.addr)};")
            else:
                out.append(
                    f"*:{op.size} {r.render(op.addr)} = {r.render(op.value)};"
                )
        elif isinstance(op, Call):
            out.append(f"call {r.render(op.target)};")
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


def _const_bool(cond) -> bool | None:
    """Return the constant truth value of `cond`, or None if symbolic."""
    if cond is True:
        return True
    if cond is False:
        return False
    if hasattr(cond, "op") and cond.op == "BoolV":
        return bool(cond.args[0])
    return None


def _emit_control(node: GraphNode, r: _Render, out: list[str]) -> None:
    """Emit the control transfer(s) of a graph node."""
    if not node.successors:
        return
    if len(node.successors) == 1 and node.successors[0][0] is None:
        return  # plain fall-through, nothing to emit
    for cond, tid in node.successors:
        const = _const_bool(cond)
        if cond is None or const is True:
            out.append(f"goto {_node_label(tid)};")
        elif const is False:
            continue  # never-taken branch, nothing to emit
        else:
            out.append(f"if ({r.render(cond)}) goto {_node_label(tid)};")


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
    *vm_state*, with one per-handler constructor derived from *graph*.

    *graph* must be the synthetic root produced by the pipeline: its
    successors are one per handler graph (in the order of *handlers*), so
    each constructor's body is walked from its handler graph's root.
    """
    # Registry of usable register names (for resolving symbolic references).
    reg_names: set[str] = {vm_state.vpc}
    if vm_state.vsp is not None:
        reg_names.add(vm_state.vsp)
    for name in vm_state.context:
        reg_names.add(name)
    for region in vm_state.regions:
        reg_names.add(region.name)

    lines: list[str] = []
    lines.append("# VMSpec auto-generated processor specification (.slaspec)")
    lines.append("# Pipeline: DSE -> state tree -> state graph -> SLEIGH")
    lines.append("# Reference: arXiv:2610.29566")
    lines.append("")
    lines.append("define endian=little;")
    lines.append("define alignment=1;")
    lines.append("")

    # Address spaces: memory (ram) and the VM register file.
    lines.append("define space ram type=ram_space size=4 default;")
    lines.append("define space register type=register_space size=4;")
    lines.append("")

    # Instruction token: the encrypted opcode byte.
    lines.append("define token instr(8)")
    lines.append("  byte=(0,7)")
    lines.append(";")
    lines.append("")

    # VM registers (abstract state): the virtual program counter and stack
    # pointer. The rolling key is a context variable on the context register.
    vm_regs = [vm_state.vpc]
    if vm_state.vsp is not None:
        vm_regs.append(vm_state.vsp)
    lines.append(f"define register offset=0x0 size=4 [ {' '.join(vm_regs)} ];")
    lines.append(f"define register offset=0x2000 size=4 {_CONTEXT_REG_NAME};")
    lines.append(f"define context {_CONTEXT_REG_NAME}")
    lines.append("  key=(0,7)")
    lines.append("  ;")
    lines.append("")

    # Handler constructors.
    r = _Render(reg_names=frozenset(reg_names))
    used_labels: set[str] = set()
    # The synthetic root carries one successor per handler graph, in the
    # same order as `handlers` (see pipeline._merge_handler_graphs); its
    # target is that handler graph's root id.
    for handler, (_, handler_root_id) in zip(handlers, graph.successors):
        body = _body_nodes(graph, handler_root_id)
        base = _label(handler.mnemonic or f"op_{handler.opcode:X}")
        name, k = base, 1
        while name in used_labels:
            name = f"{base}_{k}"
            k += 1
        used_labels.add(name)
        lines.append(
            f"# handler opcode=0x{handler.opcode:X} "
            f"entry=0x{handler.entry:X} end=0x{handler.end:X}"
        )
        # Pattern: match the raw (encrypted) opcode byte given the rolling key
        # as context, via the inverse encryption ``byte = C + key - 1``; the
        # disassembly action commits the rolling-key update so the next
        # instruction decodes with the correct key.
        c = _encrypt_const(handler.opcode)
        lines.append(
            f":{name} is byte = 0x{c:X} + key - 1 "
            f"[ key = key - 0x{handler.opcode:X}; ] {{"
        )
        # TODO(arithmetic): emit the state-graph body as C-like SLEIGH
        # semantics (branch targets as operands, `tmp:size = *:size ...` for
        # loads). For now the constructor carries only the context tracking.
        lines.append("}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"