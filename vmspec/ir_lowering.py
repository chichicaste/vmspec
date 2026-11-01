"""Translate analysis objects into VM ISA IR; this is the claripy boundary."""
from __future__ import annotations

import claripy

from . import ir
from .operand import encrypt_const
from .model import Call, GraphNode, Handler, MemAccess, VMState


_OPS = {
    "__add__": "add", "__sub__": "sub", "__mul__": "mul",
    "__and__": "and", "__or__": "or", "__xor__": "xor",
    "__lshift__": "shl", "__rshift__": "ashr", "LShR": "lshr",
    "__eq__": "eq", "__ne__": "ne",
    "ULT": "ult", "ULE": "ule", "UGT": "ugt", "UGE": "uge",
    "SLT": "slt", "SLE": "sle", "SGT": "sgt", "SGE": "sge",
    "__invert__": "invert", "__neg__": "neg",
    "And": "bool_and", "Or": "bool_or", "Xor": "bool_xor", "Not": "not",
    "ZeroExt": "zext", "SignExt": "sext", "Concat": "concat",
    "Reverse": "reverse", "If": "ite",
}


def lower_expression(value, symbols: dict[str, ir.Expr] | None = None, *, bits=32) -> ir.Expr:
    """Copy a supported expression into typed, backend-independent nodes."""
    symbols = symbols or {}
    if isinstance(value, bool):
        return ir.Expr("bool", 1, value=value)
    if isinstance(value, int):
        return ir.Expr("const", bits, value=value % (1 << bits))
    if isinstance(value, str):
        if value not in symbols:
            raise ValueError(f"unbound symbolic input: {value}")
        return symbols[value]
    if not isinstance(value, claripy.ast.Base):
        raise TypeError(f"unsupported analysis expression: {type(value).__name__}")
    op, args = value.op, value.args
    width = 1 if isinstance(value, claripy.ast.Bool) else value.size()
    if op == "BVV":
        return ir.Expr("const", width, value=args[0])
    if op == "BoolV":
        return ir.Expr("bool", 1, value=args[0])
    if op == "BVS":
        result = symbols.get(args[0])
        if result is None:
            raise ValueError(f"unbound symbolic input: {args[0]}")
        if result.bits != width:
            raise ValueError("symbol width disagrees with its definition")
        return result
    if op == "Extract":
        return ir.Expr("extract", width, (lower_expression(args[2], symbols),), args[1])
    if op not in _OPS:
        raise ValueError(f"unsupported symbolic operation: {op}")
    if op in {"ZeroExt", "SignExt"}:
        args = args[1:]
    return ir.Expr(_OPS[op], width, tuple(lower_expression(a, symbols) for a in args))


def _nodes(graph: GraphNode):
    registry = getattr(graph, "_nodes", None) or {graph.id: graph}
    result, seen, pending = [], set(), [graph.id]
    while pending:
        node_id = pending.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        if node_id not in registry:
            raise ValueError(f"missing state-graph node: {node_id}")
        node = registry[node_id]
        result.append(node)
        pending.extend(target for _, target in reversed(node.successors))
    return result


def lower_handler(handler: Handler, graph: GraphNode, vm_state: VMState, *, mode="clear", opcode=None):
    """Lower one graph without retaining ASTs or mutating its node ids."""
    if mode not in {"clear", "rolling"}:
        raise ValueError("mode must be rolling or clear")
    opcode = handler.opcode if opcode is None else opcode
    nodes = _nodes(graph)
    ids = {node.id: i for i, node in enumerate(nodes)}
    symbols = {
        name: ir.Expr("register", 32, value=name)
        for name in (vm_state.vpc, vm_state.vsp) if name is not None
    }
    count = 0
    for node in nodes:
        for op in node.ops:
            if isinstance(op, MemAccess) and op.kind == "read" and not op.forwarded:
                if not isinstance(op.value, claripy.ast.BV) or op.value.op != "BVS":
                    raise ValueError("a non-forwarded read must define a symbolic value")
                name = op.value.args[0]
                if name in symbols:
                    raise ValueError("read result has multiple definitions or shadows a register")
                symbols[name] = ir.Expr("temp", op.size * 8, value=f"read_{count}")
                count += 1
    blocks = []
    for node in nodes:
        operations = []
        for op in node.ops:
            if isinstance(op, MemAccess):
                if op.kind == "read" and op.forwarded:
                    continue
                if op.endness not in {"Iend_LE", "Iend_BE"}:
                    raise ValueError("unknown memory byte order")
                addr = lower_expression(op.addr, symbols)
                value = lower_expression(op.value, symbols, bits=op.size * 8)
                cls = ir.Read if op.kind == "read" else ir.Write
                operations.append(cls(addr, value, op.size, "little" if op.endness == "Iend_LE" else "big"))
            elif isinstance(op, Call):
                operations.append(ir.Call(lower_expression(op.target, symbols), op.site))
            else:
                raise ValueError(f"unsupported state-graph operation: {op!r}")
        branches = tuple(ir.Branch(ids[target], lower_expression(cond, symbols) if cond is not None else None)
                         for cond, target in node.successors)
        blocks.append(ir.Block(ids[node.id], tuple(operations), branches, node.addr))

    raw_opcode = ir.Expr("const", 8, value=opcode)
    updates = ()
    if mode == "rolling":
        # This frontend retains the sample's encoding; the IR stores its formula.
        constant = encrypt_const(opcode)
        key = ir.Expr("context", 8, value="key")
        raw_opcode = ir.Expr("sub", 8, (
            ir.Expr("add", 8, (ir.Expr("const", 8, value=constant), key)),
            ir.Expr("const", 8, value=1),
        ))
        updates = (ir.ContextUpdate("key", ir.Expr("sub", 8, (key, ir.Expr("const", 8, value=opcode)))),)
    return ir.Instruction(opcode, ir.Encoding(raw_opcode), ids[graph.id], tuple(blocks),
                          handler.mnemonic, context_updates=updates)


def lower_isa(built: list[tuple[Handler, GraphNode]], vm_state: VMState, dispatch_table=None, *, mode="clear"):
    if mode not in {"clear", "rolling"}:
        raise ValueError("mode must be rolling or clear")
    if dispatch_table is None:
        instructions = tuple(lower_handler(h, g, vm_state, mode=mode) for h, g in built)
    else:
        if len(dispatch_table) != 256:
            raise ValueError("dispatch_table must have 256 entries")
        by_entry = {h.entry: (h, g) for h, g in built}
        instructions = []
        for opcode, entry in enumerate(dispatch_table):
            if entry not in by_entry:
                raise ValueError(f"opcode 0x{opcode:02X} has no analyzed handler")
            h, g = by_entry[entry]
            instructions.append(lower_handler(h, g, vm_state, mode=mode, opcode=opcode))
        instructions = tuple(instructions)
    return ir.ISA(vm_state.vpc, vm_state.vsp, instructions)
