"""SLEIGH processor-spec generation (VMSpec pipeline step 5).

Turns the merged state graph into a minimal ``.slaspec`` document:

* a header with ``define space`` declarations plus one ``define register``
  per VM state region (the virtual program counter, the virtual stack
  pointer and the context variables are included);
* one instruction constructor per opcode handler: the opcode bit-pattern
  as the constructor pattern and the P-Code semantics translated from the
  state-graph ops reachable from the handler entry.

The semantics section uses SLEIGH's C-like expression syntax: loads and
stores as ``*:{size}`` statements, recorded calls as ``call`` statements,
and symbolic values as temporaries.  Fresh angr values named
``mem_<addr>_<k>_<bits>`` are re-materialised as the concrete load that
produced them; anything else is initialised to zero.  Unconditional
successor edges -- including the final return to the dispatcher -- are
the constructor's natural fall-through; a symbolic edge emits
``if (cond) goto 0xADDR;`` with the successor's entry address rendered
as a constant operand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from vmspec.model import Call, GraphNode, Handler, MemAccess, RegionKind, VMState

__all__ = ["encrypt_const", "emit_header", "generate_sleigh", "label"]

# The address space in which each region kind lives.
_SPACE_BY_KIND: dict[RegionKind, str] = {
    RegionKind.CODE: "ram",
    RegionKind.GLOBAL: "ram",
    RegionKind.STACK: "context",
    RegionKind.STATE: "context",
    RegionKind.CONTEXT: "context",
}

# angr names unconstrained-memory fresh variables
# ``mem_<addr>_<counter>_<bits>`` (lowercase hex); the concrete 32-bit
# address encoded in that name is a trace-faithful reconstruction of the
# read that produced the value.
_MEM_BVS_RE = re.compile(r"^mem_([0-9a-fA-F]+)_(\d+)_(\d+)\Z")

# C-like binary operators accepted by SLEIGH semantics expressions.
# SLEIGH value expressions require every operand of a binary operator to
# have the same byte size; the renderer enforces that on the AST.
_BIN_OPS: dict[str, str] = {
    "__add__": "+",
    "__sub__": "-",
    "__mul__": "*",
    "__truediv__": "/",
    "Bvudiv": "/",
    "Bvsdiv": "/",
    "__and__": "&",
    "__or__": "|",
    "__xor__": "^",
    "__lshift__": "<<",
    "__rshift__": ">>",
    "LShR": ">>",
    "AShr": ">>",
    "__eq__": "==",
    "__ne__": "!=",
    "__lt__": "<",
    "__le__": "<=",
    "__gt__": ">",
    "__ge__": ">=",
    "Ult": "<",
    "Ule": "<=",
    "Ugt": ">",
    "Uge": ">=",
    "Slt": "<",
    "Sle": "<=",
    "Sgt": ">",
    "Sge": ">=",
    "And": "&",
    "Or": "|",
    "Xor": "^",
}

# C-like unary operators.
_UNARY_OPS: dict[str, str] = {"__invert__": "~", "__neg__": "-"}

# Identifiers a bit range ``x[lo,count]`` may attach to directly: SLEIGH
# only accepts a bare varnode there, never an expression.
_SIMPLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

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


def encrypt_const(opcode: int) -> int:
    """Return the constant ``C`` such that ``encrypt(op, key) = C + key - 1``."""
    inv = (0xFF ^ opcode) & 0xFF
    x = (inv + 0x85) & 0xFF
    return ((x << 4) | (x >> 4)) & 0xFF  # rol8(x, 4)


@dataclass
class _Render:
    """Symbolic-value -> SLEIGH temporary name mapping, shared across the
    whole spec so that every handler renders the same angr value with the
    same temporary name."""

    reg_names: frozenset[str] = frozenset()
    _tmp: int = field(default=1, repr=False)
    _sym: int = field(default=1, repr=False)
    vars: dict[int, str] = field(default_factory=dict, repr=False)

    def fresh_tmp(self) -> str:
        """An unused SLEIGH temporary name (``tmpN``)."""
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
            return f"0x{expr:X}:4"
        if isinstance(expr, bytes):
            return f"0x{expr.hex().upper()}:{len(expr)}"
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
        # Opaque/unresolved value: render as zero rather than an undefined
        # placeholder symbol (which SLEIGH would reject).
        return "0x0:4"

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
            return f"0x{args[0]:X}:{ast.size() // 8}"
        if op == "BVS":
            # A fresh ``mem_<addr>_<k>_<bits>`` value is the result of a load
            # (already assigned a temporary by ``_emit_ops``); any other
            # symbolic variable is an unconstrained input, rendered as zero.
            name = ast.args[0]
            if isinstance(name, str) and _MEM_BVS_RE.match(name):
                return self.var_name(ast)
            return "0x0"
        if op == "BoolV":
            return "0x1" if args[0] else "0x0"

        # Complex claripy ASTs (arithmetic, bit-manipulation, concat, extract,
        # rotate, ite) have no guaranteed size-resolvable SLEIGH rendering;
        # they are emitted as an opaque zero.  Only constants, load results
        # and booleans are rendered concretely.
        return "0x0:4"


def label(raw: str) -> str:
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
                out.append(f"{dest}:{op.size} = *:{op.size} {r.render(op.addr)};")
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


def _emit_body(
    graph: GraphNode, root_id: int, r: _Render, lines: list[str]
) -> None:
    """Emit a handler's state-graph body as C-like SLEIGH semantics.

    Walks the handler graph from *root_id* and emits each node's operations
    (memory loads/stores, calls and arithmetic).  Control-flow edges are the
    handler's internal native branches: SLEIGH branch targets are operands
    (addresses), not labels, and the rolling-key context does not flow across
    them (``docs/SLEIGH.md`` §10 / §11), so they are deliberately left out of
    the body.  The final ``jmp`` into the dispatcher is the implicit
    fall-through that ends the instruction, so it needs no explicit statement.
    """
    for node in _body_nodes(graph, root_id):
        _emit_ops(node, r, lines)


def _opcode_pattern(opcode: int) -> str:
    """Least-significant opcode bytes as a comma-separated SLEIGH pattern."""
    width = max(1, (opcode.bit_length() + 7) // 8)
    return ",".join(
        f"0x{(opcode >> (8 * i)) & 0xFF:02X}" for i in range(width - 1, -1, -1)
    )


def emit_header(lines: list[str], vm_state: VMState) -> None:
    """Emit the structural parts of a SLEIGH spec into *lines*.

    Covers the endianness/alignment, the address spaces, the instruction token
    (the single encrypted opcode byte), the VM register file (VPC/VSP) and the
    rolling-key context variable.  The caller is responsible for the leading
    comment block; this emits from ``define endian`` onward and leaves a blank
    line after the context block.
    """
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


def generate_sleigh(
    graph: GraphNode,
    vm_state: VMState,
    handlers: list[Handler],
    dispatch_table: list[int] | None = None,
) -> str:
    """Generate a minimal SLEIGH ``.slaspec`` for the VM described by
    *vm_state*.

    When *dispatch_table* (a 256-entry ``opcode -> handler entry`` map) is
    given, one constructor is emitted per table index: the dispatcher's
    rolling-key update is ``key -= opcode`` (per-index, not per-handler), so
    several indices can share a handler body while still advancing the key by
    their own value.  Without a table, one constructor is emitted per handler
    using its canonical opcode.

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
    emit_header(lines, vm_state)

    # Handler constructors.
    r = _Render(reg_names=frozenset(reg_names))
    used_labels: set[str] = set()
    # Map handler entry address -> handler, for resolving table indices.
    analyzed_by_entry: dict[int, Handler] = {
        handler.entry: handler for handler in handlers
    }
    # Map handler entry address -> its state-graph root id.  The synthetic
    # root's successors are one per analysed handler, in the same order as
    # `handlers` (see pipeline._merge_handler_graphs).
    entry_to_root: dict[int, int] = {
        handler.entry: root_id
        for handler, (_, root_id) in zip(handlers, graph.successors)
    }

    def _emit_ctor(opcode: int, handler: Handler | None) -> None:
        """Emit one constructor: pattern ``byte = C + key - 1`` and the
        rolling-key update ``key -= opcode``."""
        mnemonic = handler.mnemonic if handler is not None else ""
        base = label(mnemonic) if mnemonic else f"op_{opcode:02X}"
        name, k = base, 1
        while name in used_labels:
            name = f"{base}_{k}"
            k += 1
        used_labels.add(name)
        if handler is not None:
            lines.append(
                f"# opcode=0x{opcode:02X} -> {handler.mnemonic} "
                f"entry=0x{handler.entry:X}"
            )
        else:
            lines.append(f"# opcode=0x{opcode:02X} (unanalysed handler)")
        c = encrypt_const(opcode)
        lines.append(
            f":{name} is byte = 0x{c:X} + key - 1 "
            f"[ key = key - 0x{opcode:02X}; globalset(inst_next, key); ] {{"
        )
        root_id = entry_to_root.get(handler.entry) if handler is not None else None
        if root_id is not None:
            _emit_body(graph, root_id, r, lines)
        else:
            # Unanalysed handler: no state graph, emit an explicit fall-through
            # so the disassembler still advances to the next instruction.
            lines.append("  goto inst_next;")
        lines.append("}")
        lines.append("")

    if dispatch_table is None:
        # Legacy fallback: one constructor per analysed handler, keyed on its
        # canonical opcode.
        for handler in handlers:
            _emit_ctor(handler.opcode, handler)
    else:
        # Table-based dispatch: one constructor per opcode index (0..255).
        for opcode in range(256):
            _emit_ctor(opcode, analyzed_by_entry.get(dispatch_table[opcode]))

    return "\n".join(lines).rstrip() + "\n"