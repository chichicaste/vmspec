"""Concrete execution of VM ISA IR for differential semantic validation.

No native architecture, VM family, angr, or SLEIGH dependency. Missing inputs,
unsupported calls, and violated specialization assumptions fail explicitly.
"""
from dataclasses import dataclass
from functools import reduce
import operator

from .ir import Call, Instruction, Read, RegisterWrite, Write


@dataclass(frozen=True)
class Execution:
    registers: dict[str, int]
    memory: dict[int, int]
    blocks: tuple[int, ...]


def execute(instruction: Instruction, registers: dict[str, int], memory: dict[int, int],
            *, operands=None, context=None, max_steps=10000) -> Execution:
    """Execute one instruction; memory is an explicit address-to-byte mapping.

    Operand inputs are raw field values, not decoded Operand.value expressions.
    Returned state is a copy, so multiple backends can share the same inputs.
    """
    if not isinstance(instruction, Instruction):
        raise TypeError("expected an IR instruction")
    if type(max_steps) is not int or max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if instruction.context_updates:
        raise NotImplementedError("decode-time context updates require a decoder")
    if any(type(k) is not int or k < 0 or type(v) is not int or not 0 <= v <= 255
           for k, v in memory.items()):
        raise ValueError("memory must contain nonnegative addresses and byte values")
    initial, registers, memory = dict(registers), dict(registers), dict(memory)
    inputs = {"register": registers, "initial_register": initial, "temp": {},
              "operand": dict(operands or {}), "context": dict(context or {})}

    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def evaluate(expr):
        op = expr.op
        mask = (1 << expr.bits) - 1
        if op in {"const", "bool"}:
            return expr.value
        if op in inputs:
            value = inputs[op][expr.value]
            if type(value) is not int or not 0 <= value <= mask:
                raise ValueError(f"input does not fit {expr.bits} bits: {expr.value}")
            return value
        # Evaluate only the selected arm, just as the generated control flow does.
        if op == "ite":
            return evaluate(expr.args[1 if evaluate(expr.args[0]) else 2])
        args = [evaluate(a) for a in expr.args]
        if op in {"add", "mul", "and", "or", "xor"}:
            function = {"add": operator.add, "mul": operator.mul, "and": operator.and_,
                        "or": operator.or_, "xor": operator.xor}[op]
            result = reduce(function, args)
        elif op == "sub":
            result = args[0] - args[1]
        elif op in {"shl", "lshr", "ashr"}:
            width = expr.args[0].bits
            value = signed(args[0], width) if op == "ashr" else args[0]
            if args[1] >= width:
                result = -1 if op == "ashr" and value < 0 else 0
            else:
                result = value << args[1] if op == "shl" else value >> args[1]
        elif op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
            left, right = args
            if op.startswith("s"):
                left, right = (signed(v, expr.args[0].bits) for v in args)
            predicate = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt,
                         "le": operator.le, "gt": operator.gt, "ge": operator.ge}
            return predicate[op if op in {"eq", "ne"} else op[1:]](left, right)
        elif op in {"bool_and", "bool_or", "bool_xor", "not"}:
            return {"bool_and": lambda: all(args), "bool_or": lambda: any(args),
                    "bool_xor": lambda: bool(sum(args) % 2), "not": lambda: not args[0]}[op]()
        elif op in {"neg", "invert", "zext", "sext", "extract", "reverse"}:
            value = args[0]
            if op == "neg":
                result = -value
            elif op == "invert":
                result = ~value
            elif op == "sext":
                result = signed(value, expr.args[0].bits)
            elif op == "extract":
                result = value >> expr.value
            elif op == "reverse":
                result = int.from_bytes(value.to_bytes(expr.bits // 8, "little"), "big")
            else:
                result = value
        elif op == "concat":
            result = 0
            for value, arg in zip(args, expr.args):
                result = (result << arg.bits) | value
        else:
            raise NotImplementedError(f"unsupported IR operator: {op}")
        return result & mask

    blocks = {block.id: block for block in instruction.blocks}
    current, visited = instruction.entry, []
    for _ in range(max_steps):
        block = blocks[current]
        visited.append(current)
        for assumption in block.assumptions:
            if not evaluate(assumption.condition):
                raise ValueError("input violates specialization assumption")
        for effect in block.operations:
            if isinstance(effect, RegisterWrite):
                registers[effect.register] = evaluate(effect.value)
            elif isinstance(effect, (Read, Write)):
                address = evaluate(effect.address)
                limit = 1 << effect.address.bits
                addresses = [(address + i) % limit for i in range(effect.size)]
                if isinstance(effect, Read):
                    value = int.from_bytes(bytes(memory[a] for a in addresses), effect.endian)
                    inputs["temp"][effect.result.value] = value
                else:
                    value = evaluate(effect.value).to_bytes(effect.size, effect.endian)
                    memory.update(zip(addresses, value))
            elif isinstance(effect, Call):
                raise NotImplementedError("IR calls require an explicit execution contract")
            else:
                raise TypeError("unsupported IR effect")
        edge = next((edge for edge in block.branches
                     if edge.guard is None or evaluate(edge.guard.condition)), None)
        if edge is None:
            return Execution(registers, memory, tuple(visited))
        current = edge.target
    raise RuntimeError("IR execution exceeded max_steps")
