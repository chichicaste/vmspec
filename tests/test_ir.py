import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import claripy

from tools.compile_spec import compile_slaspec, find_sleigh
from vmspec import ir
from vmspec.ir_lowering import lower_expression, lower_handler, lower_isa
from vmspec.model import Call, GraphNode, Handler, MemAccess, VMState
from vmspec.sleigh_gen import generate_sleigh


def test_opcode_encoder(opcode):
    key = ir.Expr("context", 8, value="key")
    pattern = ir.Expr("add", 8, (ir.Expr("const", 8, value=opcode), key))
    update = ir.ContextUpdate("key", ir.Expr("sub", 8, (key, ir.Expr("const", 8, value=opcode))))
    return pattern, (update,)


class IRTests(unittest.TestCase):
    def graph(self):
        value = claripy.BVS("input", 32)
        return GraphNode(7, 0x4000, [
            MemAccess("read", 0x1000, value, 4),
            MemAccess("write", 0x2000, value + 1, 4),
            Call(0x4004, 0x5000),
            MemAccess("write", 0x2004, value, 4),
        ])

    def test_ordered_effects_and_derived_views(self):
        instruction = lower_handler(Handler(3, 0x4000, 0x4010), self.graph(), VMState("VPC"))
        self.assertEqual([type(o) for o in instruction.blocks[0].operations],
                         [ir.Read, ir.Write, ir.Call, ir.Write])
        self.assertEqual(len(instruction.reads), 1)
        self.assertEqual(len(instruction.writes), 2)
        self.assertEqual(len(instruction.calls), 1)
        self.assertIn(instruction.reads[0].result, instruction.expressions)
        self.assertIsNone(instruction.operands)
        self.assertIsNone(instruction.stack_effect)
        self.assertIsNone(instruction.encoding.length)

    def test_vpc_relative_operand_is_inferred_into_ir_and_sleigh(self):
        vpc = claripy.BVS("VPC", 32, explicit_name=True)
        raw = claripy.BVS("raw_operand", 8, explicit_name=True)
        graph = GraphNode(0, 0x4000, [
            MemAccess("read", vpc, raw, 1),
            MemAccess("write", 0x2000, raw ^ 0x55, 1),
        ])
        instruction = lower_handler(Handler(7, 0x4000, 0x4010, "push_u8"), graph, VMState("VPC"))
        self.assertEqual(instruction.encoding.length, 2)
        self.assertEqual((instruction.operands[0].offset, instruction.operands[0].size), (1, 1))
        self.assertEqual(instruction.operands[0].value.op, "xor")
        self.assertEqual(len(instruction.reads), 0)
        spec = generate_sleigh(ir.ISA("VPC", None, (instruction,)))
        self.assertIn(":push_u8 is byte = 0x07; op1 {", spec)
        self.assertIn("op1 ^ 0x55:1", spec)

    def test_ir_is_json_serializable_and_deterministic(self):
        handler = Handler(3, 0x4000, 0x4010)
        first = lower_handler(handler, self.graph(), VMState("VPC"))
        second = lower_handler(handler, self.graph(), VMState("VPC"))
        self.assertEqual(first, second)
        encoded = json.dumps(dataclasses.asdict(first), sort_keys=True)
        data = json.loads(encoded)
        self.assertEqual(data["blocks"][0]["operations"][0]["result"]["value"], "read_0")
        self.assertNotIn("BVS", encoded)
        self.assertNotIn("Iend_LE", encoded)
        self.assertEqual(data["blocks"][0]["operations"][1]["value"]["op"], "add")

    def test_lowering_does_not_mutate_or_merge_handler_graphs(self):
        graph = self.graph()
        isa = lower_isa([(Handler(1, 0x4000, 0x4010), graph),
                         (Handler(2, 0x6000, 0x6010), graph)], VMState("VPC"))
        self.assertEqual(graph.id, 7)
        self.assertEqual([i.entry for i in isa.instructions], [0, 0])
        self.assertEqual([i.opcode for i in isa.instructions], [1, 2])

    def test_dispatch_aliases_keep_per_opcode_context_updates(self):
        graph = self.graph()
        isa = lower_isa([(Handler(0, 0x4000, 0x4010), graph)],
                        VMState("VPC"), [0x4000] * 256, opcode_encoder=test_opcode_encoder)
        a, b = isa.instructions[1:3]
        self.assertEqual(a.blocks, b.blocks)
        self.assertEqual(a.context_updates[0].value.args[1].value, 1)
        self.assertEqual(b.context_updates[0].value.args[1].value, 2)
        self.assertNotEqual(a.encoding, b.encoding)

    def test_expression_widths_and_signedness_survive_lowering(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        symbols = {"x": ir.Expr("register", 32, value="x")}
        self.assertEqual(lower_expression(x.SLT(0), symbols).op, "slt")
        self.assertEqual(lower_expression(x < 2, symbols).op, "ult")
        shifted = lower_expression(x >> 4, symbols)
        self.assertEqual((shifted.op, shifted.bits), ("ashr", 32))
        extracted = lower_expression(x[15:8], symbols)
        self.assertEqual((extracted.op, extracted.bits, extracted.value), ("extract", 8, 8))

    def test_ir_and_backend_import_without_analysis_dependencies(self):
        script = """
import sys
from vmspec import ir
from vmspec.sleigh_gen import generate_sleigh
address = ir.Expr("const", 32, value=4096)
value = ir.Expr("const", 32, value=42)
instruction = ir.Instruction(1, ir.Encoding(ir.Expr("const", 8, value=1), 1),
    0, (ir.Block(0, (ir.Write(address, value, 4),)),), operands=())
assert "*:4 0x1000:4 = 0x2A:4;" in generate_sleigh(ir.ISA("VPC", None, (instruction,)))
assert "angr" not in sys.modules and "claripy" not in sys.modules
"""
        result = subprocess.run([sys.executable, "-S", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_analysis_ast_is_rejected_by_ir_and_backend(self):
        with self.assertRaises(TypeError):
            ir.Expr("add", 32, (claripy.BVV(1, 32),))
        with self.assertRaises(TypeError):
            generate_sleigh(self.graph())

    def test_invalid_width_and_branch_target_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "widths differ"):
            ir.Expr("add", 32, (ir.Expr("const", 8, value=1), ir.Expr("const", 32, value=2)))
        with self.assertRaisesRegex(ValueError, "missing block"):
            ir.Instruction(1, ir.Encoding(ir.Expr("const", 8, value=1)), 0,
                           (ir.Block(0, branches=(ir.Branch(1),)),))

    def test_temporaries_must_be_defined_on_every_incoming_path(self):
        address = ir.Expr("register", 32, value="VPC")
        result = ir.Expr("temp", 32, value="r")
        guard = ir.Expr("eq", 1, (address, ir.Expr("const", 32, value=0)))
        blocks = (
            ir.Block(0, branches=(ir.Branch(1, guard), ir.Branch(2))),
            ir.Block(1, (ir.Read(address, result, 4),), (ir.Branch(3),)),
            ir.Block(2, branches=(ir.Branch(3),)),
            ir.Block(3, (ir.Write(address, result, 4),)),
        )
        with self.assertRaisesRegex(ValueError, "dominate"):
            ir.Instruction(1, ir.Encoding(ir.Expr("const", 8, value=1)), 0, blocks)

    def test_undefined_temporary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "undefined temporary"):
            ir.Instruction(1, ir.Encoding(ir.Expr("const", 8, value=1)), 0,
                (ir.Block(0, (ir.Write(ir.Expr("const", 32, value=4096),
                                      ir.Expr("temp", 32, value="missing"), 4),)),))

    def test_known_operands_are_not_silently_ignored_by_backend(self):
        instruction = lower_handler(Handler(3, 0x4000, 0x4010), self.graph(), VMState("VPC"))
        operand = ir.Operand("imm", 1, 4, ir.Expr("operand", 32, value="imm"))
        instruction = dataclasses.replace(instruction, operands=(operand,))
        with self.assertRaisesRegex(ValueError, "operand encoding"):
            generate_sleigh(ir.ISA("VPC", None, (instruction,)))

    def test_constant_context_update_declares_context_register(self):
        instruction = lower_handler(Handler(3, 0x4000, 0x4010), self.graph(), VMState("VPC"))
        instruction = dataclasses.replace(instruction, context_updates=(
            ir.ContextUpdate("key", ir.Expr("const", 8, value=3)),
        ))
        self.assertIn("define context", generate_sleigh(ir.ISA("VPC", None, (instruction,))))

    def test_temporary_names_cannot_shadow_vm_registers(self):
        register = ir.Expr("register", 32, value="VPC")
        temporary = ir.Expr("temp", 32, value="VPC")
        instruction = ir.Instruction(1, ir.Encoding(ir.Expr("const", 8, value=1)), 0,
            (ir.Block(0, (ir.Read(register, temporary, 4), ir.Write(register, temporary, 4))),))
        spec = generate_sleigh(ir.ISA("VPC", None, (instruction,)))
        self.assertNotIn("local VPC", spec)
        self.assertIn("local tmp1:4 = *:4 VPC;", spec)
        self.assertIn("*:4 VPC = tmp1;", spec)

    def test_frontend_encoded_ir_compiles_with_ghidra(self):
        try:
            compiler = find_sleigh()
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        graph = GraphNode(0, 0x4000, [MemAccess("write", 0x1000, 42, 4)])
        isa = lower_isa([(Handler(1, 0x4000, 0x4010), graph)], VMState("VPC"),
                        opcode_encoder=test_opcode_encoder)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rolling.slaspec"
            path.write_text(generate_sleigh(isa), encoding="utf-8")
            result = compile_slaspec(path, compiler)
            self.assertTrue(result.ok, result.output)


if __name__ == "__main__":
    unittest.main()
