import unittest

import angr
import claripy

from vmspec.dse import _build_tree, _concretize_unique_context, analyze_handler
from vmspec.model import Handler, MemAccess, StateNode, VMState
from vmspec.ir_lowering import lower_isa
from vmspec.sleigh_gen import generate_sleigh
from vmspec.state_graph import build_state_graph


class GraphTests(unittest.TestCase):
    def test_read_in_arithmetic_is_live(self):
        x = claripy.BVS("x", 32)
        root = StateNode(1, [
            MemAccess("read", 0x1000, x, 4),
            MemAccess("write", 0x2000, x + 1, 4),
        ])
        graph = build_state_graph(root)
        self.assertEqual(len(graph.ops), 2)

    def test_guard_keeps_read(self):
        x = claripy.BVS("x", 32)
        root = StateNode(1, [MemAccess("read", 0x1000, x, 4)])
        root.successors = [StateNode(2, cond=x == 0), StateNode(3, cond=x != 0)]
        self.assertEqual(len(build_state_graph(root).ops), 1)

    def test_forwarded_read_does_not_redefine_value(self):
        x = claripy.BVS("x", 32)
        root = StateNode(1, [
            MemAccess("read", 0x1000, x, 4),
            MemAccess("read", 0x2000, x, 4, forwarded=True),
            MemAccess("write", 0x3000, x + 1, 4),
        ])
        self.assertEqual(len(build_state_graph(root).ops), 2)

    def test_write_retained_when_other_branch_exits(self):
        root = StateNode(1, [MemAccess("write", 0x1000, 1, 4)])
        root.successors = [StateNode(2, [MemAccess("write", 0x1000, 2, 4)]), StateNode(3)]
        self.assertEqual(len(build_state_graph(root).ops), 1)

    def test_different_guards_do_not_merge(self):
        x = claripy.BVS("x", 32)
        leaf = StateNode(4)
        a, b = StateNode(2), StateNode(2)
        a.successors = [StateNode(3, successors=[leaf], cond=x == 0)]
        b.successors = [StateNode(3, successors=[leaf], cond=x == 1)]
        graph = build_state_graph(StateNode(1, successors=[a, b]))
        self.assertNotEqual(graph.successors[0][1], graph.successors[1][1])


class DSETests(unittest.TestCase):
    def test_unique_context_value_is_specialized_with_a_guard(self):
        project = angr.load_shellcode(b"\x90", arch="x86", load_address=0x4000)
        state = project.factory.blank_state(addr=0x4000)
        state.regs.esi = claripy.BVS("esi", 32, explicit_name=True)
        state.add_constraints(state.regs.esi == 0x1234)

        self.assertEqual(_concretize_unique_context([state], ["esi"]), 1)
        self.assertTrue(state.regs.esi.concrete)
        tree = _build_tree([state], entry=0x4000)
        self.assertEqual(len(tree.successors), 1)
        self.assertTrue(tree.successors[0].cond.symbolic)
        handler = Handler(1, 0x4000, 0x4001, "context")
        isa = lower_isa([(handler, build_state_graph(tree))], VMState("eip", context=["esi"]))
        spec = generate_sleigh(isa)
        self.assertIn("define register offset=0x0 size=4 [ eip esi ];", spec)
        self.assertIn("(esi == 0x1234:4)", spec)

    def test_branch_load_is_before_guard_and_stores_are_path_local(self):
        # mov eax,[esi]; test eax,eax; jz true; mov [edi],1; jmp end;
        # true: mov [edi],2; end: nop
        code = bytes.fromhex("8b0685c07408c70701000000eb06c7070200000090")
        project = angr.load_shellcode(code, arch="x86", load_address=0x4000)
        tree = analyze_handler(project, Handler(1, 0x4000, 0x4014), VMState("esi", "edi"), max_steps=8)
        paths = []
        def visit(node, ops, guards):
            ops = ops + node.mem_ops
            if node.cond is not None and node.cond.symbolic:
                self.assertTrue(any(op.kind == "read" for op in ops))
                guards = guards + [node.cond]
            if not node.successors:
                paths.append((ops, guards))
            for child in node.successors:
                visit(child, ops, guards)
        visit(tree, [], [])
        self.assertEqual(len(paths), 2)
        reads = [ops[0] for ops, _ in paths]
        self.assertIs(reads[0], reads[1])
        self.assertEqual(
            sorted(op.value.args[0] for ops, _ in paths for op in ops if op.kind == "write"),
            [1, 2],
        )
        graph = build_state_graph(tree)
        self.assertEqual(sum(op.kind == "read" for n in graph._nodes.values() for op in n.ops), 1)

    def test_register_update_is_recorded_and_lowered(self):
        project = angr.load_shellcode(bytes.fromhex("4690"), arch="x86", load_address=0x4000)
        handler = Handler(1, 0x4000, 0x4001, "inc")
        graph = build_state_graph(analyze_handler(project, handler, VMState("esi"), max_steps=2))
        isa = lower_isa([(handler, graph)], VMState("esi"))
        self.assertEqual(isa.instructions[0].register_writes[0].register, "esi")
        self.assertIn("define register offset=0x0 size=4 [ esi ];", generate_sleigh(isa))
        self.assertIn("esi = (0x1:4 + esi);", generate_sleigh(isa))

    def test_in_binary_native_call_is_specialized_inline(self):
        # call 0x4007; nop; nop; 0x4007: inc esi; ret
        code = bytes.fromhex("e802000000909046c3")
        project = angr.load_shellcode(code, arch="x86", load_address=0x4000)
        handler = Handler(1, 0x4000, 0x4006, "native")
        tree = analyze_handler(project, handler, VMState("esi"), max_steps=8)
        graph = build_state_graph(tree)
        isa = lower_isa([(handler, graph)], VMState("esi"))
        self.assertEqual(len(isa.instructions[0].calls), 0)
        self.assertEqual(isa.instructions[0].register_writes[0].register, "esi")

    def test_truncated_handler_is_rejected(self):
        project = angr.load_shellcode(bytes.fromhex("ebfe"), arch="x86", load_address=0x4000)
        with self.assertRaisesRegex(RuntimeError, "incomplete DSE"):
            analyze_handler(project, Handler(1, 0x4000, 0x5000), VMState("esi"), max_steps=2)


if __name__ == "__main__":
    unittest.main()
