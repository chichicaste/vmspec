"""VM instruction IR, independent of angr, claripy and SLEIGH.

Expressions use explicit bit widths and normalized operators. Blocks own the
ordered effects; instruction-wide lists are derived views of those blocks.
All stored fields contain only dataclasses, tuples and Python scalars.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


_BINARY = {"add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "ashr"}
_COMPARE = {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}
_BOOLEAN = {"bool_and", "bool_or", "bool_xor", "not"}


@dataclass(frozen=True)
class Expr:
    op: str
    bits: int
    args: tuple[Expr, ...] = ()
    value: int | str | bool | None = None

    def __post_init__(self):
        if type(self.bits) is not int or self.bits <= 0:
            raise ValueError("expression width must be positive")
        if not isinstance(self.args, tuple) or any(not isinstance(a, Expr) for a in self.args):
            raise TypeError("IR expression arguments must be Expr tuples")
        op, args = self.op, self.args
        if op in {"const", "bool", "register", "initial_register", "context", "temp", "operand"}:
            if args:
                raise ValueError("leaf expression cannot have arguments")
            if op == "const" and (type(self.value) is not int or not 0 <= self.value < 1 << self.bits):
                raise ValueError("constant does not fit its bit width")
            if op == "bool" and (type(self.value) is not bool or self.bits != 1):
                raise ValueError("boolean constant requires one bit")
            if op in {"register", "initial_register", "context", "temp", "operand"} and (
                not isinstance(self.value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.value)
            ):
                raise ValueError("invalid IR symbol name")
            return
        if op == "extract":
            if len(args) != 1 or type(self.value) is not int or self.value < 0 or self.value + self.bits > args[0].bits:
                raise ValueError("invalid bit extraction")
        elif self.value is not None:
            raise ValueError("only leaves and extracts carry a value")
        if op in _BINARY | _COMPARE:
            if len(args) < 2 or (op not in {"add", "mul", "and", "or", "xor"} and len(args) != 2):
                raise ValueError("invalid binary expression arity")
            if any(a.is_bool for a in args):
                raise ValueError("bitvector operation received a boolean")
            if op not in {"shl", "lshr", "ashr"} and any(a.bits != args[0].bits for a in args):
                raise ValueError("operand widths differ")
            if self.bits != (1 if op in _COMPARE else args[0].bits):
                raise ValueError("incorrect result width")
        elif op in _BOOLEAN:
            if len(args) < (1 if op == "not" else 2) or (op == "not" and len(args) != 1):
                raise ValueError("invalid boolean arity")
            if self.bits != 1 or not all(a.is_bool for a in args):
                raise ValueError("boolean operation requires boolean operands")
        elif op in {"neg", "invert", "zext", "sext", "reverse", "extract"}:
            if len(args) != 1 or args[0].is_bool:
                raise ValueError("invalid unary bitvector expression")
            if op in {"neg", "invert", "reverse"} and self.bits != args[0].bits:
                raise ValueError("unary expression changes width")
            if op in {"zext", "sext"} and self.bits < args[0].bits:
                raise ValueError("extension narrows its input")
            if op == "reverse" and self.bits % 8:
                raise ValueError("byte reversal requires a whole number of bytes")
        elif op == "concat":
            if len(args) < 2 or any(a.is_bool for a in args) or self.bits != sum(a.bits for a in args):
                raise ValueError("invalid concatenation")
        elif op == "ite":
            if len(args) != 3 or not args[0].is_bool:
                raise ValueError("conditional expression requires a boolean guard")
            if args[1].bits != self.bits or args[2].bits != self.bits or args[1].is_bool != args[2].is_bool:
                raise ValueError("conditional values have different types")
        else:
            raise ValueError(f"unsupported IR expression: {op}")

    @property
    def is_bool(self):
        return self.op in _COMPARE | _BOOLEAN | {"bool"} or (
            self.op == "ite" and self.args[1].is_bool
        )


@dataclass(frozen=True)
class Encoding:
    opcode: Expr
    # None means that the complete instruction length has not been recovered.
    length: int | None = None

    def __post_init__(self):
        if not isinstance(self.opcode, Expr) or self.opcode.is_bool or self.opcode.bits != 8:
            raise ValueError("current encoding requires an eight-bit opcode expression")
        if self.length is not None and (type(self.length) is not int or self.length < 1):
            raise ValueError("instruction length must be positive")


@dataclass(frozen=True)
class Operand:
    name: str
    offset: int
    size: int
    value: Expr

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name or type(self.offset) is not int or type(self.size) is not int or self.offset < 0 or self.size <= 0 or not isinstance(self.value, Expr):
            raise ValueError("invalid operand description")


@dataclass(frozen=True)
class Read:
    address: Expr
    result: Expr
    size: int
    endian: str = "little"

    def __post_init__(self):
        _memory_types(self.address, self.result, self.size, self.endian)
        if self.result.op != "temp":
            raise ValueError("a read must define a temporary")


@dataclass(frozen=True)
class Write:
    address: Expr
    value: Expr
    size: int
    endian: str = "little"

    def __post_init__(self):
        _memory_types(self.address, self.value, self.size, self.endian)


@dataclass(frozen=True)
class RegisterWrite:
    register: str
    value: Expr

    def __post_init__(self):
        Expr("register", 32, value=self.register)
        if not isinstance(self.value, Expr) or self.value.is_bool or self.value.bits != 32:
            raise ValueError("register writes currently require 32-bit values")


def _memory_types(address, value, size, endian):
    if not isinstance(address, Expr) or not isinstance(value, Expr):
        raise TypeError("memory effects require IR expressions")
    if address.is_bool or value.is_bool or type(size) is not int or size <= 0 or value.bits != size * 8:
        raise ValueError("invalid memory effect width")
    if endian not in {"little", "big"}:
        raise ValueError("invalid memory byte order")


@dataclass(frozen=True)
class Call:
    target: Expr
    site: int | None = None

    def __post_init__(self):
        if not isinstance(self.target, Expr) or self.target.is_bool:
            raise TypeError("call target must be an IR address expression")
        if self.site is not None and type(self.site) is not int:
            raise TypeError("call source address must be an integer")


@dataclass(frozen=True)
class BranchGuard:
    condition: Expr

    def __post_init__(self):
        if not isinstance(self.condition, Expr) or not self.condition.is_bool:
            raise ValueError("branch guard must be boolean")


@dataclass(frozen=True)
class ContextAssumption:
    """Analysis metadata; it must never be emitted as executable control flow."""

    condition: Expr

    def __post_init__(self):
        if not isinstance(self.condition, Expr) or not self.condition.is_bool:
            raise ValueError("context assumption must be boolean")


@dataclass(frozen=True)
class Branch:
    target: int
    guard: BranchGuard | None = None

    def __post_init__(self):
        if type(self.target) is not int:
            raise TypeError("branch target must be a block id")
        if self.guard is not None and not isinstance(self.guard, BranchGuard):
            raise TypeError("branch guard must be a BranchGuard")


@dataclass(frozen=True)
class ContextUpdate:
    """Decode-time context assignment; runtime effects belong in blocks."""
    name: str
    value: Expr

    def __post_init__(self):
        if not isinstance(self.value, Expr) or self.value.is_bool:
            raise ValueError("context update requires a bitvector expression")
        Expr("context", self.value.bits, value=self.name)


@dataclass(frozen=True)
class Block:
    id: int
    operations: tuple[Read | Write | RegisterWrite | Call, ...] = ()
    branches: tuple[Branch, ...] = ()
    source_address: int | None = None
    assumptions: tuple[ContextAssumption, ...] = ()

    def __post_init__(self):
        if type(self.id) is not int:
            raise TypeError("block id must be an integer")
        if self.source_address is not None and type(self.source_address) is not int:
            raise TypeError("block source address must be an integer")
        if not isinstance(self.operations, tuple) or any(not isinstance(o, (Read, Write, RegisterWrite, Call)) for o in self.operations):
            raise TypeError("block operations must be IR effects")
        if not isinstance(self.branches, tuple) or any(not isinstance(b, Branch) for b in self.branches):
            raise TypeError("block branches must be IR branches")
        if not isinstance(self.assumptions, tuple) or any(not isinstance(a, ContextAssumption) for a in self.assumptions):
            raise TypeError("block assumptions must be IR context assumptions")


@dataclass(frozen=True)
class Instruction:
    opcode: int
    encoding: Encoding
    entry: int
    blocks: tuple[Block, ...]
    mnemonic: str = ""
    operands: tuple[Operand, ...] | None = None
    stack_effect: Expr | None = None
    context_updates: tuple[ContextUpdate, ...] = ()

    def __post_init__(self):
        if type(self.entry) is not int or not isinstance(self.mnemonic, str):
            raise TypeError("instruction requires an integer entry and string mnemonic")
        if type(self.opcode) is not int or not 0 <= self.opcode <= 255:
            raise ValueError("opcode must fit in one byte")
        if not isinstance(self.encoding, Encoding):
            raise TypeError("instruction requires an IR encoding")
        if not isinstance(self.blocks, tuple) or any(not isinstance(b, Block) for b in self.blocks):
            raise TypeError("instruction blocks must be an IR tuple")
        ids = {b.id for b in self.blocks}
        if len(ids) != len(self.blocks) or self.entry not in ids:
            raise ValueError("duplicate block ids or missing entry")
        if any(edge.target not in ids for block in self.blocks for edge in block.branches):
            raise ValueError("branch targets a missing block")
        if self.operands is not None and (
            not isinstance(self.operands, tuple) or any(not isinstance(o, Operand) for o in self.operands)
        ):
            raise TypeError("operands must be an IR tuple or unknown")
        if self.stack_effect is not None and (
            not isinstance(self.stack_effect, Expr) or self.stack_effect.is_bool
        ):
            raise TypeError("stack effect must be a bitvector expression or unknown")
        if not isinstance(self.context_updates, tuple) or any(not isinstance(c, ContextUpdate) for c in self.context_updates):
            raise TypeError("context updates must be an IR tuple")
        self._validate_flow()

    def _validate_flow(self):
        blocks = {b.id: b for b in self.blocks}
        predecessors = {b.id: set() for b in self.blocks}
        reached, pending = set(), [self.entry]
        while pending:
            block_id = pending.pop()
            if block_id in reached:
                continue
            reached.add(block_id)
            for edge in blocks[block_id].branches:
                predecessors[edge.target].add(block_id)
                pending.append(edge.target)
        if reached != set(blocks):
            raise ValueError("instruction contains unreachable blocks")
        dominators = {n: ({n} if n == self.entry else set(blocks)) for n in blocks}
        changed = True
        while changed:
            changed = False
            for n in blocks:
                if n == self.entry:
                    continue
                new = {n} | set.intersection(*(dominators[p] for p in predecessors[n]))
                if new != dominators[n]:
                    dominators[n] = new
                    changed = True
        definitions = {}
        for block in self.blocks:
            for index, op in enumerate(block.operations):
                if isinstance(op, Read):
                    name = op.result.value
                    if name in definitions:
                        raise ValueError("temporary has multiple definitions")
                    definitions[name] = (block.id, index, op.result.bits)
        for block in self.blocks:
            uses = []
            for index, op in enumerate(block.operations):
                expressions = ((op.address,) if isinstance(op, Read) else
                               (op.address, op.value) if isinstance(op, Write) else
                               (op.value,) if isinstance(op, RegisterWrite) else (op.target,))
                uses.extend((index, e) for e in expressions)
            uses.extend((len(block.operations), e.guard.condition) for e in block.branches if e.guard is not None)
            for index, expression in uses:
                pending = [expression]
                while pending:
                    expr = pending.pop()
                    if expr.op == "temp":
                        definition = definitions.get(expr.value)
                        if definition is None:
                            raise ValueError(f"undefined temporary: {expr.value}")
                        owner, position, bits = definition
                        if bits != expr.bits or owner not in dominators[block.id] or (owner == block.id and position >= index):
                            raise ValueError("temporary definition does not dominate its use")
                    pending.extend(expr.args)

    @property
    def reads(self):
        return tuple(o for b in self.blocks for o in b.operations if isinstance(o, Read))

    @property
    def writes(self):
        return tuple(o for b in self.blocks for o in b.operations if isinstance(o, Write))

    @property
    def calls(self):
        return tuple(o for b in self.blocks for o in b.operations if isinstance(o, Call))

    @property
    def register_writes(self):
        return tuple(o for b in self.blocks for o in b.operations if isinstance(o, RegisterWrite))

    @property
    def branches(self):
        return tuple(edge for block in self.blocks for edge in block.branches)

    @property
    def expressions(self):
        roots = [self.encoding.opcode]
        for block in self.blocks:
            for op in block.operations:
                if isinstance(op, Read):
                    roots.extend((op.address, op.result))
                elif isinstance(op, Write):
                    roots.extend((op.address, op.value))
                elif isinstance(op, RegisterWrite):
                    roots.append(op.value)
                else:
                    roots.append(op.target)
            roots.extend(b.guard.condition for b in block.branches if b.guard is not None)
        roots.extend(o.value for o in self.operands or ())
        roots.extend(c.value for c in self.context_updates)
        if self.stack_effect is not None:
            roots.append(self.stack_effect)
        seen = {}
        pending = list(reversed(roots))
        while pending:
            expr = pending.pop()
            if expr not in seen:
                seen[expr] = None
                pending.extend(reversed(expr.args))
        return tuple(seen)


@dataclass(frozen=True)
class ISA:
    vpc: str
    vsp: str | None
    instructions: tuple[Instruction, ...]
    registers: tuple[str, ...] = ()

    def __post_init__(self):
        Expr("register", 32, value=self.vpc)
        if self.vsp is not None:
            Expr("register", 32, value=self.vsp)
        if not isinstance(self.registers, tuple):
            raise TypeError("ISA registers must be a tuple")
        if len(set(self.registers)) != len(self.registers):
            raise ValueError("duplicate ISA register")
        declared = {self.vpc, *self.registers}
        if self.vsp is not None:
            declared.add(self.vsp)
        for register in self.registers:
            Expr("register", 32, value=register)
        if any(
            op.register not in declared
            for instruction in self.instructions
            for block in instruction.blocks
            for op in block.operations
            if isinstance(op, RegisterWrite)
        ):
            raise ValueError("register write target is not declared in the ISA")
        if not isinstance(self.instructions, tuple) or any(not isinstance(i, Instruction) for i in self.instructions):
            raise TypeError("ISA requires an instruction tuple")
        if len({i.opcode for i in self.instructions}) != len(self.instructions):
            raise ValueError("duplicate instruction opcode")
