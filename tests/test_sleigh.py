import tempfile
import unittest
from pathlib import Path

import angr
import claripy

from tools.compile_spec import compile_slaspec, find_sleigh
from vmspec.dse import analyze_handler
from vmspec.model import GraphNode, Handler, MemAccess, VMState
from vmspec.ir import Block, Encoding, Expr, Instruction, ISA, Operand, RegisterWrite, Write
from vmspec.ir_lowering import lower_expression, lower_isa
from vmspec.sleigh_gen import _Render, generate_sleigh
from vmspec.state_graph import build_state_graph


def branch_spec():
    code = bytes.fromhex("8b0685c07408c70701000000eb06c7070200000090")
    project = angr.load_shellcode(code, arch="x86", load_address=0x4000)
    handler = Handler(1, 0x4000, 0x4014, "branch")
    vm = VMState("esi", "edi")
    tree = analyze_handler(project, handler, vm, max_steps=8)
    isa = lower_isa([(handler, build_state_graph(tree))], vm)
    return generate_sleigh(isa)



def execute_branch_pcode(context, operations, input_value):
    """Small test interpreter for the operations emitted by the branch fixture."""
    spaces = {"ram": {}, "register": {}, "unique": {}}

    def load(space, offset, size):
        return sum(spaces[space].get(offset + i, 0) << (i * 8) for i in range(size))

    def store(space, offset, size, value):
        for i in range(size):
            spaces[space][offset + i] = (value >> (i * 8)) & 0xFF

    def read(v):
        return v.offset if v.space.name == "const" else load(v.space.name, v.offset, v.size)

    for name, value in (("esi", 0x1000), ("edi", 0x2000)):
        reg = context.registers[name]
        store("register", reg.offset, reg.size, value)
    store("ram", 0x1000, 4, input_value)
    pc = 0
    for _ in range(100):
        if pc == len(operations):
            return load("ram", 0x2000, 4)
        op = operations[pc]
        name = op.opcode.name
        ins = op.inputs
        result = None
        if name == "IMARK":
            pass
        elif name == "COPY":
            result = read(ins[0])
        elif name == "LOAD":
            result = load("ram", read(ins[1]), op.output.size)
        elif name == "STORE":
            store("ram", read(ins[1]), ins[2].size, read(ins[2]))
        elif name in ("INT_EQUAL", "INT_NOTEQUAL"):
            result = int((read(ins[0]) == read(ins[1])) == (name == "INT_EQUAL"))
        elif name == "BOOL_NEGATE":
            result = int(not read(ins[0]))
        elif name in ("CBRANCH", "BRANCH"):
            if name == "BRANCH" or read(ins[1]):
                target = ins[0]
                assert target.space.name == "const", "fixture must branch within the instruction"
                delta = target.offset
                if delta >= 1 << (target.size * 8 - 1):
                    delta -= 1 << (target.size * 8)
                pc += delta
                continue
        else:
            raise AssertionError(f"unsupported fixture operation: {op}")
        if result is not None:
            store(op.output.space.name, op.output.offset, op.output.size, result)
        pc += 1
    raise AssertionError("fixture did not terminate")

class SleighTests(unittest.TestCase):
    def test_native_branches_use_local_labels(self):
        spec = branch_spec()
        self.assertIn("if (", spec)
        self.assertIn("goto <node_", spec)
        self.assertIn("goto <handler_end>;", spec)
        self.assertIn("*:4 edi = 0x1:4;", spec)
        self.assertIn("*:4 edi = 0x2:4;", spec)
        self.assertNotIn(":branch is byte = 0x01; op4", spec)
        self.assertEqual(spec.count("= *:4 esi;"), 1)

    def test_unbound_inputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unbound"):
            lower_expression(claripy.BVS("unknown", 32))

    def test_unsupported_ast_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            lower_expression(claripy.RotateLeft(claripy.BVS("x", 32, explicit_name=True), 3))

    def test_arithmetic_and_signedness(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        r = _Render(reg_names=frozenset({"x"}))
        symbols = {"x": Expr("register", 32, value="x")}
        self.assertIn("+", r.render(lower_expression(x + 1, symbols)))
        self.assertIn("s<", r.render(lower_expression(x.SLT(0), symbols)))
        self.assertIn("s>>", r.render(lower_expression(x >> 1, symbols)))
        self.assertNotIn("s>>", r.render(lower_expression(claripy.LShR(x, 1), symbols)))

    def test_missing_handler_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no analyzed handler"):
            lower_isa([], VMState("VPC"), [0] * 256)

    def test_generated_branch_compiles_with_ghidra(self):
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "branch.slaspec"
            path.write_text(branch_spec(), encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)

    def test_register_write_compiles_with_ghidra(self):
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        instruction = Instruction(
            1, Encoding(Expr("const", 8, value=1), 1), 0,
            (Block(0, (RegisterWrite("VSP", Expr("const", 32, value=4)),)),),
            operands=(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "register_write.slaspec"
            path.write_text(generate_sleigh(ISA("VPC", "VSP", (instruction,))), encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)

    def test_multiple_inline_operands_compile_with_ghidra(self):
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        first = Expr("operand", 8, value="op1")
        second = Expr("operand", 8, value="op1_2")
        instruction = Instruction(
            1, Encoding(Expr("const", 8, value=1), 3), 0,
            (Block(0, (
                Write(Expr("const", 32, value=0x1000), first, 1),
                Write(Expr("const", 32, value=0x1001), second, 1),
            )),),
            operands=(Operand("op1", 1, 1, first), Operand("op1_2", 2, 1, second)),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "multiple_operands.slaspec"
            path.write_text(generate_sleigh(ISA("VPC", None, (instruction,))), encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)

    def test_expression_widths_compile_with_ghidra(self):
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        x = claripy.BVS("VPC", 32, explicit_name=True)
        y = claripy.BVS("VSP", 32, explicit_name=True)
        values = [
            x + y, x - y, x * y, x & y, x | y, x ^ y,
            x >> y, claripy.LShR(x, y), x << y, ~x, -x,
            x[15:0].zero_extend(16), x[15:0].sign_extend(16),
            claripy.Concat(x[7:0], x[15:8], x[23:16], x[31:24]),
            claripy.Reverse(x), claripy.If(x.SLT(y), x + 1, y - 1),
        ]
        handler = Handler(1, 1, 2, "expr")
        body = GraphNode(0, 1, [
            MemAccess("write", 0x1000 + i * 4, value, 4) for i, value in enumerate(values)
        ])
        isa = lower_isa([(handler, body)], VMState("VPC", "VSP"))
        spec = generate_sleigh(isa)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expr.slaspec"
            path.write_text(spec, encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)

    def test_compiled_pcode_matches_native_branch(self):
        try:
            import pypcode
        except ImportError:
            self.skipTest("pypcode is unavailable")
        import xml.etree.ElementTree as ET
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "branch.slaspec"
            path.write_text(branch_spec(), encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)
            (Path(tmp) / "branch.pspec").write_text("<processor_spec/>", encoding="utf-8")
            language = pypcode.ArchLanguage(tmp, ET.fromstring(
                '<language id="test:LE:32:default" processor="test" endian="little" '
                'size="32" variant="default" slafile="branch.sla" processorspec="branch.pspec"/>'
            ))
            context = pypcode.Context(language)
            operations = context.translate(bytes([1]), max_instructions=1).ops
            native = angr.load_shellcode(
                bytes.fromhex("8b0685c07408c70701000000eb06c7070200000090"),
                arch="x86", load_address=0x4000,
            )
            for value in (0, 1, 0x80000000, 0xFFFFFFFF):
                state = native.factory.blank_state(addr=0x4000)
                state.regs.esi, state.regs.edi = 0x1000, 0x2000
                state.memory.store(0x1000, claripy.BVV(value, 32), endness="Iend_LE")
                states = native.factory.simgr(state).explore(find=0x4014).found
                self.assertEqual(len(states), 1)
                expected = states[0].solver.eval(states[0].memory.load(0x2000, 4, endness="Iend_LE"))
                self.assertEqual(execute_branch_pcode(context, operations, value), expected)


if __name__ == "__main__":
    unittest.main()
