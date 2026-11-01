"""Regression tests using synthetic states; no private VM blob is required."""
import unittest

import angr
import claripy

from vmspec.memory import install
from vmspec.model import Region, RegionKind, VMState


class MemoryTests(unittest.TestCase):
    def state(self, regions=()):
        state = angr.SimState(arch="X86")
        install(state, vm_state=VMState("esi", regions=list(regions)))
        return state

    def test_symbolic_write_read_does_not_constrain_pointer(self):
        s = self.state()
        ptr = claripy.BVS("ptr", 32)
        value = claripy.BVS("value", 32)
        before = list(s.solver.constraints)
        s.memory.store(ptr, value, endness="Iend_LE")
        result = s.memory.load(ptr, 4, endness="Iend_LE")
        self.assertTrue(s.solver.is_true(result == value))
        self.assertFalse(claripy.Solver().satisfiable(extra_constraints=[claripy.And(*before) != claripy.And(*s.solver.constraints)]))

    def test_fresh_reads_without_write(self):
        s = self.state()
        ptr = claripy.BVS("ptr", 32)
        a = s.memory.load(ptr, 4)
        b = s.memory.load(ptr, 4)
        self.assertNotEqual(a.variables, b.variables)
        self.assertFalse(s.solver.constraints)

    def test_partial_read_respects_endianness(self):
        for write_endness in ("Iend_LE", "Iend_BE"):
            for read_endness in ("Iend_LE", "Iend_BE"):
                with self.subTest(write=write_endness, read=read_endness):
                    s = self.state()
                    ptr = claripy.BVS("ptr", 32)
                    s.memory.store(ptr, claripy.BVV(0x11223344, 32), endness=write_endness)
                    result = s.memory.load(ptr + 1, 2, endness=read_endness)
                    expected = 0x2233 if write_endness == read_endness else 0x3322
                    self.assertEqual(s.solver.eval(result), expected)

    def test_partial_overlap_invalidates_whole_cached_write(self):
        s = self.state()
        ptr = claripy.BVS("ptr", 32)
        s.memory.store(ptr, claripy.BVV(0x11223344, 32))
        s.memory.store(ptr + 1, claripy.BVV(0xFF, 8))
        self.assertTrue(s.memory.load(ptr, 4).symbolic)
        self.assertEqual(s.solver.eval(s.memory.load(ptr + 1, 1)), 0xFF)

    def test_possible_alias_invalidates(self):
        s = self.state()
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        s.memory.store(x, claripy.BVV(1, 32))
        s.memory.store(y, claripy.BVV(2, 32))
        self.assertTrue(s.memory.load(x, 4).symbolic)

    def test_disjoint_regions_preserve_cached_values(self):
        s = self.state([
            Region("stack", RegionKind.STACK, 0x1000, 0x100),
            Region("state", RegionKind.STATE, 0x2000, 0x100),
        ])
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        s.add_constraints(x >= 0x1000, x <= 0x10FC, y >= 0x2000, y <= 0x20FC)
        before = list(s.solver.constraints)
        s.memory.store(x, claripy.BVV(1, 32))
        s.memory.store(y, claripy.BVV(2, 32))
        self.assertEqual([w.region for w in s.vmspec_recorder.recent_writes], [0, 1])
        self.assertEqual(s.solver.eval(s.memory.load(x, 4)), 1)
        self.assertFalse(claripy.Solver().satisfiable(extra_constraints=[claripy.And(*before) != claripy.And(*s.solver.constraints)]))

    def test_forks_have_independent_cache(self):
        s = self.state()
        ptr = claripy.BVS("ptr", 32)
        s.memory.store(ptr, claripy.BVV(1, 32))
        child = s.copy()
        child.memory.store(ptr, claripy.BVV(2, 32))
        self.assertEqual(s.solver.eval(s.memory.load(ptr, 4)), 1)
        self.assertEqual(child.solver.eval(child.memory.load(ptr, 4)), 2)
        self.assertEqual(len(s.vmspec_recorder.mem_ops), 2)

    def test_readonly_unique_address_reads_image(self):
        s = self.state([Region("ro", RegionKind.READONLY, 0x1000, 4)])
        s.memory.store(0x1000, claripy.BVV(0x12345678, 32), inspect=False)
        ptr = claripy.BVS("ptr", 32)
        s.add_constraints(ptr == 0x1000)
        before = list(s.solver.constraints)
        self.assertEqual(s.solver.eval(s.memory.load(ptr, 4)), 0x12345678)
        self.assertFalse(claripy.Solver().satisfiable(extra_constraints=[claripy.And(*before) != claripy.And(*s.solver.constraints)]))

    def test_readonly_multivalued_pointer_stays_symbolic(self):
        s = self.state([Region("ro", RegionKind.READONLY, 0x1000, 8)])
        ptr = claripy.BVS("ptr", 32)
        s.add_constraints(claripy.Or(ptr == 0x1000, ptr == 0x1004))
        self.assertTrue(s.memory.load(ptr, 4).symbolic)
        self.assertEqual(len(s.solver.eval_upto(ptr, 3)), 2)

    def test_mutable_image_data_is_not_assumed_constant(self):
        s = self.state()
        s.memory.store(0x1000, claripy.BVV(123, 32), inspect=False)
        self.assertTrue(s.memory.load(0x1000, 4).symbolic)

    def test_readonly_writes_rejected(self):
        s = self.state([Region("ro", RegionKind.READONLY, 0x1000, 4)])
        with self.assertRaisesRegex(ValueError, "read-only"):
            s.memory.store(0x1000, claripy.BVV(1, 32))

    def test_symbolic_size_rejected(self):
        s = self.state()
        with self.assertRaisesRegex(ValueError, "size"):
            s.memory.load(0x1000, claripy.BVS("size", 32))


if __name__ == "__main__":
    unittest.main()
