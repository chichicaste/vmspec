"""SLEIGH backend for the independent VM ISA IR."""

from __future__ import annotations

from dataclasses import dataclass, field

from .ir import ISA, Block, Call, Expr, Instruction, Read, Write
from .model import VMState

__all__ = ["emit_header", "generate_sleigh", "label"]

_BIN_OPS = {
    "add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^",
    "shl": "<<", "lshr": ">>", "ashr": "s>>", "eq": "==", "ne": "!=",
    "ult": "<", "ule": "<=", "ugt": ">", "uge": ">=",
    "slt": "s<", "sle": "s<=", "sgt": "s>", "sge": "s>=",
    "bool_and": "&&", "bool_or": "||", "bool_xor": "^",
}

_CONTEXT_REG_NAME = "contextreg"


@dataclass
class _Render:
    """Translate typed IR expressions; analysis objects never enter the backend."""

    reg_names: frozenset[str] = frozenset()
    temporaries: frozenset[str] = frozenset()
    _tmp: int = 1
    prelude: list[str] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)

    def fresh_tmp(self):
        while True:
            name = f"tmp{self._tmp}"
            self._tmp += 1
            if name not in self.reg_names | self.temporaries:
                return name

    def temporary(self, expression, size):
        name = self.fresh_tmp()
        self.prelude.append(f"local {name}:{size} = {expression};")
        return name

    def render(self, expr: Expr):
        if not isinstance(expr, Expr):
            raise TypeError("SLEIGH requires IR expressions")
        op, args = expr.op, expr.args
        if not expr.is_bool and expr.bits % 8 and op != "extract":
            raise ValueError("non-byte-sized bitvector operation is not supported")
        if op == "const":
            return f"0x{expr.value:X}:{expr.bits // 8}"
        if op == "bool":
            return "1:1" if expr.value else "0:1"
        if op in {"register", "temp"}:
            names = self.reg_names if op == "register" else self.temporaries
            if expr.value not in names:
                raise ValueError(f"unbound IR input: {expr.value}")
            if op == "register" and expr.bits != 32:
                raise ValueError("SLEIGH VM registers currently require 32 bits")
            if op == "temp":
                if expr.value not in self.bindings:
                    self.bindings[expr.value] = self.fresh_tmp()
                return self.bindings[expr.value]
            return expr.value
        if op in _BIN_OPS:
            return "(" + f" {_BIN_OPS[op]} ".join(self.render(a) for a in args) + ")"
        if op in {"invert", "neg", "not"}:
            operator = {"invert": "~", "neg": "-", "not": "!"}[op]
            return f"({operator}{self.render(args[0])})"
        if op in {"zext", "sext"}:
            if args[0].bits % 8:
                raise ValueError("non-byte-sized extension is not supported")
            return self.temporary(f"{op}({self.render(args[0])})", expr.bits // 8)
        if op == "extract":
            if args[0].bits % 8:
                raise ValueError("extraction from a non-byte-sized value is not supported")
            value = self.temporary(self.render(args[0]), args[0].bits // 8)
            return f"{value}[{expr.value},{expr.bits}]"
        if op == "concat":
            if any(a.bits % 8 for a in args):
                raise ValueError("non-byte-sized concatenation is not supported")
            size, shift, parts = expr.bits // 8, expr.bits, []
            for arg in args:
                shift -= arg.bits
                part = self.temporary(f"zext({self.render(arg)})", size)
                parts.append(f"({part} << {shift})" if shift else part)
            return "(" + " | ".join(parts) + ")"
        if op == "reverse":
            if expr.bits == 8:
                return self.render(args[0])
            parts = tuple(Expr("extract", 8, args, offset) for offset in range(0, expr.bits, 8))
            return self.render(Expr("concat", expr.bits, parts))
        if op == "ite":
            cond = self.render(args[0])
            size = 1 if expr.is_bool else expr.bits // 8
            result = self.fresh_tmp()
            yes_label, end = result + "_yes", result + "_end"
            self.prelude.extend([f"local {result}:{size};", f"if ({cond}) goto <{yes_label}>;"])
            no = self.render(args[2])
            self.prelude.extend([f"{result} = {no};", f"goto <{end}>;", f"<{yes_label}>"])
            yes = self.render(args[1])
            self.prelude.extend([f"{result} = {yes};", f"<{end}>"])
            return result
        raise ValueError(f"unsupported IR expression in SLEIGH: {op}")


def label(raw: str) -> str:
    """Sanitise *raw* into a valid SLEIGH label."""
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in raw)
    if not out or out[0].isdigit():
        out = "op_" + out
    return out or "op"


def _node_label(node_id: int) -> str:
    return f"node_{node_id}"


def _body_nodes(instruction: Instruction):
    registry = {block.id: block for block in instruction.blocks}
    result, seen, pending = [], set(), [instruction.entry]
    while pending:
        node_id = pending.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        node = registry[node_id]
        result.append(node)
        pending.extend(edge.target for edge in reversed(node.branches))
    return result


def _emit_ops(node: Block, r: _Render, out: list[str]) -> None:
    for op in node.operations:
        if isinstance(op, (Read, Write)):
            if op.endian != "little":
                raise ValueError("SLEIGH memory effects currently require little endian")
            if op.address.bits != 32:
                raise ValueError("SLEIGH addresses currently require 32 bits")
            addr = r.render(op.address)
            if isinstance(op, Read):
                line = f"local {r.render(op.result)}:{op.size} = *:{op.size} {addr};"
            else:
                line = f"*:{op.size} {addr} = {r.render(op.value)};"
        elif isinstance(op, Call):
            if op.target.bits != 32:
                raise ValueError("SLEIGH call targets currently require 32 bits")
            line = f"call [{r.render(op.target)}];"
        else:
            raise TypeError("SLEIGH requires IR effects")
        out.extend(r.prelude)
        r.prelude.clear()
        out.append(line)


def _const_bool(cond: Expr | None) -> bool | None:
    return cond.value if cond is not None and cond.op == "bool" else None


def _emit_control(node: Block, r: _Render, out: list[str]) -> None:
    for edge in node.branches:
        cond, tid = edge.condition, edge.target
        const = _const_bool(cond)
        if cond is None or const is True:
            out.append(f"goto <{_node_label(tid)}>;")
            return
        if const is False:
            continue
        expr = r.render(cond)
        out.extend(r.prelude)
        r.prelude.clear()
        out.append(f"if ({expr}) goto <{_node_label(tid)}>;")
    out.append("goto <handler_end>;")


def _emit_body(instruction: Instruction, r: _Render, lines: list[str]) -> None:
    body = _body_nodes(instruction)
    targets = {instruction.entry}
    for node in body:
        for edge in node.branches:
            if _const_bool(edge.condition) is not False:
                targets.add(edge.target)
            if edge.condition is None or _const_bool(edge.condition) is True:
                break
    lines.append(f"goto <{_node_label(instruction.entry)}>;")
    for node in body:
        if node.id in targets:
            lines.append(f"<{_node_label(node.id)}>")
        _emit_ops(node, r, lines)
        _emit_control(node, r, lines)
    lines.append("<handler_end>")


def emit_header(lines: list[str], vm_state: VMState | ISA, *, with_context: bool = True) -> None:
    """Emit the structural parts of a SLEIGH spec into *lines*.

    Covers the endianness/alignment, the address spaces, the instruction token
    (the single opcode byte), the VM register file (VPC/VSP) and -- when
    *with_context* is true -- the rolling-key context variable.  The caller is
    responsible for the leading comment block; this emits from ``define endian``
    onward and leaves a blank line after the context block (or the register
    block when there is no context).
    """
    lines.append("define endian=little;")
    lines.append("define alignment=1;")
    lines.append("")

    # Address spaces: memory (ram) and the VM register file.
    lines.append("define space ram type=ram_space size=4 default;")
    lines.append("define space register type=register_space size=4;")
    lines.append("")

    # Instruction token: the (encrypted or clear) opcode byte, plus one token
    # per operand width. A constructor concatenates its operand token with `;`
    # so the instruction length is exactly 1 + operand_size bytes (a single
    # oversized token would force every instruction to its full width).
    lines.append("define token instr(8)")
    lines.append("  byte=(0,7)")
    lines.append(";")
    lines.append("define token data8(8)")
    lines.append("  op1=(0,7)")
    lines.append(";")
    lines.append("define token data16(16)")
    lines.append("  op2=(0,15)")
    lines.append(";")
    lines.append("define token data32(32)")
    lines.append("  op4=(0,31)")
    lines.append(";")
    lines.append("")

    # VM registers (abstract state): the virtual program counter and stack
    # pointer. The rolling key (when used) is a context variable on a context
    # register.
    vm_regs = [vm_state.vpc]
    if vm_state.vsp is not None:
        vm_regs.append(vm_state.vsp)
    lines.append(f"define register offset=0x0 size=4 [ {' '.join(vm_regs)} ];")
    if with_context:
        lines.append(f"define register offset=0x2000 size=4 {_CONTEXT_REG_NAME};")
        lines.append(f"define context {_CONTEXT_REG_NAME}")
        lines.append("  key=(0,7)")
        lines.append("  ;")
    lines.append("")


def _pattern(expr: Expr) -> str:
    """Render the supported decode-time expression subset."""
    if expr.op == "const":
        return f"0x{expr.value:02X}"
    if expr.op == "context" and expr.value == "key" and expr.bits == 8:
        return "key"
    if expr.op in {"add", "sub"}:
        return "(" + f" {'+' if expr.op == 'add' else '-'} ".join(_pattern(a) for a in expr.args) + ")"
    raise ValueError(f"unsupported encoding/context expression: {expr.op}")


def generate_sleigh(isa: ISA) -> str:
    """Generate SLEIGH from VM ISA IR only.

    The backend currently emits opcode-only instructions. Known operand
    encodings outside that subset fail explicitly; unknown encodings remain
    marked as such in the specification.
    """
    if not isinstance(isa, ISA):
        raise TypeError("generate_sleigh requires VM ISA IR")
    with_context = any(i.context_updates or any(e.op == "context" for e in i.expressions) for i in isa.instructions)
    names = frozenset(n for n in (isa.vpc, isa.vsp) if n is not None)
    lines = [
        "# VMSpec processor specification (.slaspec)",
        "# Pipeline: DSE -> state graph -> VM ISA IR -> SLEIGH",
        "",
    ]
    emit_header(lines, isa, with_context=with_context)
    used_labels = set()
    for instruction in isa.instructions:
        if instruction.operands or instruction.encoding.length not in (None, 1):
            raise ValueError("operand encoding lowering is not implemented")
        base = label(instruction.mnemonic) if instruction.mnemonic else f"op_{instruction.opcode:02X}"
        name, k = base, 1
        while name in used_labels:
            name = f"{base}_{k}"
            k += 1
        used_labels.add(name)
        lines.append(f"# opcode=0x{instruction.opcode:02X}")
        if instruction.operands is None or instruction.encoding.length is None:
            lines.append("# Operand encoding unresolved; opcode-only constructor.")
        updates = []
        for update in instruction.context_updates:
            if update.name != "key" or update.value.bits != 8:
                raise ValueError("unsupported context field")
            updates.append(f"key = {_pattern(update.value)}; globalset(inst_next, key);")
        action = "[ " + " ".join(updates) + " ] " if updates else ""
        lines.append(f":{name} is byte = {_pattern(instruction.encoding.opcode)} {action}{{")
        renderer = _Render(names, frozenset(read.result.value for read in instruction.reads))
        _emit_body(instruction, renderer, lines)
        lines.extend(("}", ""))
    return "\n".join(lines).rstrip() + "\n"
