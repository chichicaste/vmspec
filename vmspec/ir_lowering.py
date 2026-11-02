"""Translate analysis objects into VM ISA IR; this is the claripy boundary."""
from __future__ import annotations

from collections.abc import Callable

import claripy

from . import ir
from .model import Call, GraphNode, Handler, MemAccess, RegisterAccess, VMState


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


def _vpc_offset(address, vpc_name):
    """Return a constant offset for VPC-relative addresses, else None."""
    if not isinstance(address, claripy.ast.BV):
        return None
    if address.op == "BVS":
        return 0 if address.args[0] == vpc_name else None
    if address.op in {"__add__", "__sub__"} and len(address.args) == 2:
        left, right = address.args
        if right.op == "BVV":
            base = _vpc_offset(left, vpc_name)
            if base is not None:
                delta = right.args[0]
                return base + (delta if address.op == "__add__" else -delta)
        if address.op == "__add__" and left.op == "BVV":
            base = _vpc_offset(right, vpc_name)
            if base is not None:
                return base + left.args[0]
    return None


def _operand_reads(nodes, vpc_name):
    candidates = [(op, _vpc_offset(op.addr, vpc_name)) for node in nodes for op in node.ops
                  if isinstance(op, MemAccess) and op.kind == "read" and not op.forwarded]
    candidates = [(op, offset) for op, offset in candidates if offset is not None and offset >= 1]
    if not candidates:
        return None
    inferred = []
    variables = set()
    consumers = [
        expr
        for node in nodes
        for expr in (
            [value for op in node.ops for value in (
                (op.addr, op.value) if isinstance(op, MemAccess) else
                (op.value,) if isinstance(op, RegisterAccess) else
                (op.target,) if isinstance(op, Call) else ()
            )]
            + [guard.condition for guard, _ in node.successors if guard is not None]
        )
    ]
    for read, relative in candidates:
        if not isinstance(read.value, claripy.ast.BV) or read.value.op != "BVS":
            continue
        variable = read.value.args[0]
        if not any(variable in getattr(expr, "variables", ()) for expr in consumers):
            continue
        if read.size not in (1, 2, 4) or variable in variables:
            return None
        variables.add(variable)
        decoded = next((op.value for node in nodes for op in node.ops if isinstance(op, MemAccess)
                        and op.kind == "write" and variable in getattr(op.value, "variables", ())), read.value)
        inferred.append((read, relative, decoded))
    if not inferred:
        return None
    inferred.sort(key=lambda item: item[1])
    if len({offset for _, offset, _ in inferred}) != len(inferred):
        return None
    cursor = 1
    for read, offset, _ in inferred:
        if offset != cursor:
            return None
        cursor += read.size
    return tuple(inferred)


def _operand_name(index, size):
    field = {1: "op1", 2: "op2", 4: "op4"}[size]
    return field if index == 0 else f"{field}_{index + 1}"


def lower_handler(handler: Handler, graph: GraphNode, vm_state: VMState, *, opcode=None,
                  opcode_encoder: Callable[[int], tuple[ir.Expr, tuple[ir.ContextUpdate, ...]]] | None = None):
    """Lower one graph without retaining ASTs or mutating its node ids."""
    opcode = handler.opcode if opcode is None else opcode
    nodes = _nodes(graph)
    ids = {node.id: i for i, node in enumerate(nodes)}
    inferred = _operand_reads(nodes, vm_state.vpc)
    operands = None
    operand_symbols = {}
    if inferred is not None:
        operands = tuple(
            ir.Operand(
                _operand_name(index, read.size), offset, read.size,
                operand_symbols.setdefault(
                    read.value.args[0], ir.Expr("operand", read.size * 8, value=_operand_name(index, read.size))
                ),
            )
            for index, (read, offset, _) in enumerate(inferred)
        )
    symbols = {
        name: ir.Expr("register", 32, value=name)
        for name in (vm_state.vpc, vm_state.vsp, *vm_state.context) if name is not None
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
                symbols[name] = operand_symbols.get(name, ir.Expr("temp", op.size * 8, value=f"read_{count}"))
                count += 1
    blocks = []
    for node in nodes:
        operations = []
        for op in node.ops:
            if isinstance(op, MemAccess):
                if op.kind == "read" and op.forwarded:
                    continue
                if inferred is not None and any(op is read for read, _, _ in inferred):
                    continue
                if op.endness not in {"Iend_LE", "Iend_BE"}:
                    raise ValueError("unknown memory byte order")
                addr = lower_expression(op.addr, symbols)
                value = lower_expression(op.value, symbols, bits=op.size * 8)
                cls = ir.Read if op.kind == "read" else ir.Write
                operations.append(cls(addr, value, op.size, "little" if op.endness == "Iend_LE" else "big"))
            elif isinstance(op, Call):
                operations.append(ir.Call(lower_expression(op.target, symbols), op.site))
            elif isinstance(op, RegisterAccess):
                operations.append(ir.RegisterWrite(
                    op.register, lower_expression(op.value, symbols, bits=op.size * 8)
                ))
            else:
                raise ValueError(f"unsupported state-graph operation: {op!r}")
        branches = tuple(ir.Branch(
            ids[target], ir.BranchGuard(lower_expression(guard.condition, symbols)) if guard else None
        ) for guard, target in node.successors)
        assumptions = tuple(ir.ContextAssumption(lower_expression(item.condition, symbols))
                            for item in node.assumptions)
        blocks.append(ir.Block(ids[node.id], tuple(operations), branches, node.addr, assumptions))

    raw_opcode = ir.Expr("const", 8, value=opcode)
    updates = ()
    if opcode_encoder is not None:
        raw_opcode, updates = opcode_encoder(opcode)
        if not isinstance(raw_opcode, ir.Expr) or any(not isinstance(u, ir.ContextUpdate) for u in updates):
            raise TypeError("opcode_encoder must return an IR expression and context-update tuple")
    if inferred is not None:
        operands = tuple(
            ir.Operand(
                _operand_name(index, read.size), offset, read.size,
                lower_expression(decoded, symbols, bits=read.size * 8),
            )
            for index, (read, offset, decoded) in enumerate(inferred)
        )
        length = max(offset + read.size for read, offset, _ in inferred)
    else:
        length = None
    return ir.Instruction(opcode, ir.Encoding(raw_opcode, length), ids[graph.id], tuple(blocks),
                          handler.mnemonic, operands=operands, context_updates=updates)


def lower_isa(
    built: list[tuple[Handler, GraphNode]], vm_state: VMState, dispatch_table=None, *,
    opcode_encoder: Callable[[int], tuple[ir.Expr, tuple[ir.ContextUpdate, ...]]] | None = None,
):
    if dispatch_table is None:
        instructions = tuple(lower_handler(h, g, vm_state, opcode_encoder=opcode_encoder) for h, g in built)
    else:
        if len(dispatch_table) != 256:
            raise ValueError("dispatch_table must have 256 entries")
        by_entry = {h.entry: (h, g) for h, g in built}
        instructions = []
        for opcode, entry in enumerate(dispatch_table):
            if entry not in by_entry:
                raise ValueError(f"opcode 0x{opcode:02X} has no analyzed handler")
            h, g = by_entry[entry]
            instructions.append(lower_handler(h, g, vm_state, opcode=opcode, opcode_encoder=opcode_encoder))
        instructions = tuple(instructions)
    registers = tuple(sorted(
        set(vm_state.context) |
        {op.register for instruction in instructions
         for block in instruction.blocks for op in block.operations
         if isinstance(op, ir.RegisterWrite)}
    ))
    return ir.ISA(vm_state.vpc, vm_state.vsp, instructions, registers)
