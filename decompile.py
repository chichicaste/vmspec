"""Replay the Unicorn opcode trace through the VM handler semantics.

The emulator already produced a *correct* opcode trace (op + oper + rolling key).
This module replays that trace against the handler semantics recovered in
``keysched.py``, but logs *high-level* operations (S-box reads/writes, DATA
memory traffic, stack constants, subroutine calls/returns) with concrete values.

Usage:
    python decompile.py [--trace PATH] [--limit N] [--start N] [--data-only]
"""
from __future__ import annotations

import argparse
import json
import os
import struct

ENGINE = 0x1AE1000
DATA = 0x1AE5000
DISP = 0x16E0000
M = 0xFFFFFFFF

# F1/F2 output slots (inside dbin image)
SLOT_F1 = ENGINE + 0x1224
SLOT_F2 = ENGINE + 0x1234

KEY_ALPH = "12345789ABCDFGHJKLMQRSTVWXYZ+=@%"   # 32 chars, at dbin 0x14B7
ROT_ALPH = "A7FH8LWS4DZC3MXG2YR9JK1TQ5BV1234"    # 28 chars, at dbin 0x149B
CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"       # 32 chars, at dbin 0x15D7


def _ror8(x, n):
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF if n & 7 else x


def _rol8(x, n):
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF if n & 7 else x


# Initial host frame values used by the Unicorn emulator (see emu_unicorn.py)
VM_RET = 0xDEAD0000
ECM_ADDR = 0x30000200
F1_OUT = 0x30000000
F2_OUT = 0x30000100


class VM:
    def __init__(self, dbin: bytes):
        self.dbin = dbin
        self.mem: dict[int, int] = {}
        self.esp = 0x2000FFC0
        self.key = 0
        self.eflags = None  # actual EFLAGS captured by the emulator at pushfd
        # seed data region from dbin[0x4000..0x40FF]
        for i in range(0x2000):
            self.mem[DATA + i] = dbin[0x4000 + i] if i < 0x100 else 0

    def seed_frame(self, esp_base: int):
        """Reconstruct the 16-dword return frame the dispatcher left on the stack.

        Pop order (frame[i] = [esp_base + i*4]): DISP, ecx, edi, ebp, EFLAGS,
        ebx, eax, edx, ebx, esi, key, entry-marker, then the trampoline args.
        """
        frame = [DISP, 0, 0, 0, 0x2, 0, 0, 0, 0, 0,   # DISP + 9 saved regs (EFLAGS=0x2)
                 0x407575, 0xD546DCFF,                 # key, entry marker
                 VM_RET, ECM_ADDR, F1_OUT, F2_OUT]     # trampoline args
        for i, v in enumerate(frame):
            self.wr32(esp_base + i * 4, v)

    def rd(self, a, n):
        out = bytearray()
        for i in range(n):
            x = (a + i) & M
            if x in self.mem:
                out.append(self.mem[x])
            else:
                off = x - ENGINE
                out.append(self.dbin[off] if 0 <= off < len(self.dbin) else 0)
        return bytes(out)

    def wr(self, a, data):
        for i, b in enumerate(data):
            self.mem[(a + i) & M] = b

    def rd16(self, a): return int.from_bytes(self.rd(a, 2), 'little')
    def rd32(self, a): return int.from_bytes(self.rd(a, 4), 'little')
    def wr16(self, a, v): self.wr(a, v.to_bytes(2, 'little'))
    def wr32(self, a, v): self.wr(a, v.to_bytes(4, 'little'))
    def push(self, v, n):
        self.esp = (self.esp - n) & M
        self.wr(self.esp, v.to_bytes(n, 'little'))

    def push_flags(self):
        """Push the actual EFLAGS captured by the emulator at this opcode's pushfd."""
        self.push(self.eflags if self.eflags is not None else 0, 4)
    def pop(self, n):
        v = int.from_bytes(self.rd(self.esp, n), 'little')
        self.esp = (self.esp + n) & M
        return v
    def peek(self, k=0, n=4):
        return int.from_bytes(self.rd((self.esp + k) & M, n), 'little')


# ---- handler semantics (ported from keysched.py) --------------------------
# Each handler is (mnemonic, operand_size, fn(vm, op, oper_bytes, log)).
# oper_bytes = the RAW (still-obfuscated) operand bytes following the opcode.

def _decode_byte_oper(vm, b):
    """The common per-handler byte-operand decode (0x00A/0x08E family)."""
    al = (b + vm.key) & 0xFF
    al = (-al) & 0xFF
    al ^= 0x65
    al = (al - 0xFB) & 0xFF
    al ^= 0xA1
    al = (al + 1) & 0xFF
    al ^= 0x96
    al = _rol8(al, 7)
    al = (al - 0xD5) & 0xFF
    vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) + al) & 0xFF)
    return al


def _decode_byte_oper2(vm, b):
    """The other byte-operand decode (0x065/0x12B family)."""
    al = (b ^ vm.key) & 0xFF
    al = (al - 1) & 0xFF
    al = (~al) & 0xFF
    al = (al - 0x3C) & 0xFF
    al = (-al) & 0xFF
    al ^= 0x88
    al = _rol8(al, 1)
    vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ al) & 0xFF)
    return al


def _decode_byte_oper3(vm, b):
    """0x7F4/0xB54 family decode."""
    al = (b ^ vm.key) & 0xFF
    al = _ror8(al, 2)
    al = (al + 1) & 0xFF
    al = (-al) & 0xFF
    al = (~al) & 0xFF
    vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ al) & 0xFF)
    return al


def _decode_imm16(vm, b2):
    v16 = int.from_bytes(b2, 'little')
    cx = (v16 - (vm.key & 0xFFFF)) & 0xFFFF
    cx = (cx - 0x6C11) & 0xFFFF
    cx = (~cx) & 0xFFFF
    cx = (((cx & 0xFF) << 8) | (cx >> 8)) & 0xFFFF
    cx = (~cx) & 0xFFFF
    vm.key = (vm.key & ~0xFFFF) | (((vm.key & 0xFFFF) - cx) & 0xFFFF)
    return cx


def _flags_add(a, b):
    r = (a + b) & M
    cf = 1 if (a + b) > M else 0
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    of = 1 if ((a ^ r) & (b ^ r) & 0x80000000) else 0
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    af = 1 if ((a ^ b ^ r) & 0x10) else 0
    return 0x2 | cf | (pf << 2) | (af << 4) | (zf << 6) | (sf << 7) | (of << 11)


def _flags_logic(r):
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    return 0x2 | (pf << 2) | (zf << 6) | (sf << 7)


def _flags_shift(r, cf):
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    return 0x2 | cf | (pf << 2) | (zf << 6) | (sf << 7)


HANDLERS = {}


def reg(off, mnem, size=0):
    def deco(fn):
        HANDLERS[off] = (mnem, size, fn)
        return fn
    return deco


@reg(0x00A, "ld_sbox16", 1)
def _(vm, op, b, log):
    al = _decode_byte_oper(vm, b[0])
    v = vm.rd16(DATA + al)
    log(f"push SBOX[{al}] = 0x{v:04x} '{chr(v & 0xff) if 32 <= v & 0xff < 127 else '?'}'")
    vm.push(v, 2)


@reg(0x02D, "ld_data", 0)
def _(vm, op, b, log):
    a = DATA + (op & 0x3C)
    v = vm.rd32(a)
    log(f"push DATA[{a - DATA:#x}] = 0x{v:08x}")
    vm.push(v, 4)


@reg(0x038, "ld_imm16", 2)
def _(vm, op, b, log):
    cx = _decode_imm16(vm, b)
    log(f"push imm16 0x{cx:04x} ({cx})")
    vm.push(cx, 2)


@reg(0x058, "ld_mem8", 0)
@reg(0x0C9, "ld_mem8", 0)
@reg(0x2A5, "ld_mem8", 0)
def _(vm, op, b, log):
    a = vm.pop(4)
    v = vm.rd(a, 1)[0]
    log(f"push mem8[0x{a:08x}] = 0x{v:02x} '{chr(v) if 32 <= v < 127 else '?'}'")
    vm.push(v, 2)


@reg(0x065, "ld_imm8", 1)
def _(vm, op, b, log):
    al = _decode_byte_oper2(vm, b[0])
    log(f"push imm8 0x{al:02x} ({al})")
    vm.push(al, 2)


@reg(0x07F, "shr16", 0)
def _(vm, op, b, log):
    dx = vm.pop(2); cx = vm.pop(2)
    vm.push((dx >> (cx & 0x1F)) & 0xFFFF, 2); vm.push_flags()


@reg(0x08E, "st_sbox16", 1)
def _(vm, op, b, log):
    al = _decode_byte_oper(vm, b[0])
    v = vm.pop(2)
    log(f"SBOX[{al}] = 0x{v:04x} '{chr(v & 0xff) if 32 <= v & 0xff < 127 else '?'}'")
    vm.wr16(DATA + al, v)


@reg(0x0B0, "and_not16", 0)
def _(vm, op, b, log):
    t = (~vm.peek()) & M
    vm.wr32(vm.esp, t)
    cx = vm.pop(2)
    v16 = vm.peek(0, 2) & cx
    vm.wr16(vm.esp, v16)
    vm.push_flags()


@reg(0x0BF, "push_esp16", 0)
def _(vm, op, b, log):
    vm.push(vm.esp & 0xFFFF, 2)


@reg(0x0D4, "shl16", 0)
def _(vm, op, b, log):
    dx = vm.pop(2); cx = vm.pop(2)
    dl = (dx & 0xFF) << (cx & 0x1F) & 0xFF
    vm.push((dx & 0xFF00) | dl, 2); vm.push_flags()


@reg(0x0E2, "push_esp32", 0)
def _(vm, op, b, log):
    vm.push(vm.esp, 4)


@reg(0x0EB, "st_mem32", 0)
@reg(0x163, "st_mem32", 0)
@reg(0x27F, "st_mem32", 0)
def _(vm, op, b, log):
    a = vm.pop(4); v = vm.pop(4)
    log(f"mem32[0x{a:08x}] = 0x{v:08x}")
    vm.wr32(a, v)


@reg(0x0F4, "mul32", 0)
def _(vm, op, b, log):
    edx = vm.pop(4); eax = vm.pop(4)
    p = eax * edx
    vm.push(p & M, 4); vm.push((p >> 32) & M, 4); vm.push_flags()


@reg(0x10F, "and16", 0)
def _(vm, op, b, log):
    ax = vm.pop(2); dx = vm.pop(2)
    al8 = (~ax & dx) & 0xFF
    vm.push((ax & 0xFF00) | al8, 2); vm.push_flags()


@reg(0x12B, "ld_imm32s", 1)
def _(vm, op, b, log):
    cl = _decode_byte_oper2(vm, b[0])
    v = (cl - 256) & M if cl & 0x80 else cl
    log(f"push imm32s 0x{v:08x} ({v if v < 0x80000000 else v - 0x100000000})")
    vm.push(v, 4)


@reg(0x14D, "ld_imm32", 4)
def _(vm, op, b, log):
    c4 = int.from_bytes(b, 'little')
    ecx = (c4 - vm.key) & M
    ecx = (ecx + 1) & M
    ecx = (-ecx) & M
    ecx = ((ecx >> 5) | (ecx << 27)) & M
    ecx = (ecx - 1) & M
    vm.key = (vm.key - ecx) & M
    log(f"push imm32 0x{ecx:08x} ({ecx})")
    vm.push(ecx, 4)


@reg(0x16C, "add32", 0)
def _(vm, op, b, log):
    v4 = vm.pop(4); a = vm.peek()
    vm.wr32(vm.esp, (a + v4) & M)
    vm.push_flags()


@reg(0x176, "drop", 0)
def _(vm, op, b, log):
    vm.pop(4)


@reg(0x1B5, "shrd32", 0)
def _(vm, op, b, log):
    eax = vm.pop(4); edx = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
    r = ((eax >> sh) | (edx << (32 - sh))) & M if sh else eax
    vm.push(r, 4); vm.push_flags()


@reg(0x1C3, "add16", 0)
def _(vm, op, b, log):
    v4 = vm.pop(2); a = vm.peek(0, 2)
    vm.wr16(vm.esp, (a + v4) & 0xFFFF)
    vm.push_flags()


@reg(0x267, "shl16", 0)
def _(vm, op, b, log):
    dx = vm.pop(2); cx = vm.pop(2)
    vm.push((dx << (cx & 0x1F)) & 0xFFFF, 2); vm.push_flags()


@reg(0x276, "ld_mem32", 0)
@reg(0x2BC, "ld_mem32", 0)
def _(vm, op, b, log):
    a = vm.pop(4)
    v = vm.rd32(a)
    log(f"push mem32[0x{a:08x}] = 0x{v:08x}")
    vm.push(v, 4)


@reg(0x287, "add8", 0)
def _(vm, op, b, log):
    v4 = vm.pop(2); a = vm.peek(0, 1)
    vm.wr(vm.esp, ((a + v4) & 0xFF).to_bytes(1, 'little'))
    vm.push_flags()


@reg(0x292, "set_esp", 0)
def _(vm, op, b, log):
    vm.esp = vm.pop(4)


@reg(0x29A, "st_mem8", 0)
@reg(0x2B1, "st_mem8", 0)
@reg(0xB88, "st_mem8", 0)
def _(vm, op, b, log):
    a = vm.pop(4); v4 = vm.pop(2)
    log(f"mem8[0x{a:08x}] = 0x{v4 & 0xff:02x} '{chr(v4 & 0xff) if 32 <= v4 & 0xff < 127 else '?'}'")
    vm.wr(a, (v4 & 0xFF).to_bytes(1, 'little'))


@reg(0x2D1, "shr16b", 0)
def _(vm, op, b, log):
    dx = vm.pop(2); cx = vm.pop(2)
    dl = (dx & 0xFF) >> (cx & 0x1F)
    vm.push((dx & 0xFF00) | dl, 2); vm.push_flags()


@reg(0x2DF, "div64", 0)
def _(vm, op, b, log):
    edx = vm.pop(4); eax = vm.pop(4); ecx = vm.pop(4)
    dd = (edx << 32) | eax
    vm.push((dd // ecx) & M, 4); vm.push((dd % ecx) & M, 4); vm.push_flags()


@reg(0x2EC, "and_not32", 0)
def _(vm, op, b, log):
    a = (~vm.pop(4)) & M
    t = (~vm.peek()) & M
    vm.wr32(vm.esp, t)
    t = vm.peek() & a
    vm.wr32(vm.esp, t)
    vm.push_flags()


@reg(0x2FB, "st_mem16", 0)
@reg(0xB7E, "st_mem16", 0)
@reg(0xB99, "st_mem16", 0)
def _(vm, op, b, log):
    a = vm.pop(4); v16 = vm.pop(2)
    log(f"mem16[0x{a:08x}] = 0x{v16:04x}")
    vm.wr16(a, v16)


@reg(0x304, "call", 0)
def _(vm, op, b, log):
    v = vm.pop(4); pk = vm.peek()
    vm.key = v
    pc = (v + pk) & M
    log(f"CALL -> bytecode 0x{pc - ENGINE:05x} (key=0x{v:08x})")


@reg(0x30A, "shr32", 0)
def _(vm, op, b, log):
    eax = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
    vm.push((eax >> sh) & M, 4)
    vm.push_flags()


@reg(0x7E9, "ret_native", 0)
def _(vm, op, b, log):
    for _ in range(10):
        vm.pop(4)
    ra = vm.pop(4)
    log(f"RETURN to 0x{ra:08x}")


@reg(0x7F4, "ld_sbox8", 1)
def _(vm, op, b, log):
    al = _decode_byte_oper3(vm, b[0])
    v = vm.rd(DATA + al, 1)[0]
    log(f"push SBOX[{al}] = 0x{v:02x} '{chr(v) if 32 <= v < 127 else '?'}'")
    vm.push(v, 2)


@reg(0x810, "imul32", 0)
def _(vm, op, b, log):
    edx = vm.pop(4); eax = vm.pop(4)
    p = ((eax ^ 0x80000000) - 0x80000000) * ((edx ^ 0x80000000) - 0x80000000)
    vm.push(p & M, 4); vm.push((p >> 32) & M, 4); vm.push_flags()


@reg(0x81C, "ld_imm32w", 2)
def _(vm, op, b, log):
    ax = _decode_imm16(vm, b)
    log(f"push imm32w 0x{ax:08x} ({ax})")
    vm.push(ax, 4)


@reg(0xB40, "ld_mem16", 0)
@reg(0xBB1, "ld_mem16", 0)
def _(vm, op, b, log):
    a = vm.pop(4)
    v = vm.rd16(a)
    log(f"push mem16[0x{a:08x}] = 0x{v:04x}")
    vm.push(v, 2)


@reg(0xB49, "st_data", 0)
def _(vm, op, b, log):
    a = DATA + (op & 0x3C)
    v = vm.pop(4)
    log(f"DATA[{a - DATA:#x}] = 0x{v:08x}")
    vm.wr32(a, v)


@reg(0xB54, "st_sbox8", 1)
def _(vm, op, b, log):
    al = _decode_byte_oper3(vm, b[0])
    v = vm.pop(2)
    log(f"SBOX[{al}] = 0x{v & 0xff:02x} '{chr(v & 0xff) if 32 <= v & 0xff < 127 else '?'}'")
    vm.wr(DATA + al, (v & 0xFF).to_bytes(1, 'little'))


@reg(0xB92, "set_esp16", 0)
def _(vm, op, b, log):
    v4 = vm.pop(2)
    vm.esp = (vm.esp & 0xFFFF0000) | v4


@reg(0xBA3, "shld32", 0)
def _(vm, op, b, log):
    eax = vm.pop(4); edx = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
    r = ((eax << sh) | (edx >> (32 - sh))) & M if sh else eax
    vm.push(r, 4); vm.push_flags()


@reg(0xBBB, "shl32", 0)
def _(vm, op, b, log):
    eax = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
    r = (eax << sh) & M
    vm.push(r, 4)
    vm.push_flags()


def replay(trace_ops, dbin, jt, start=0, limit=None, log_out=None, flags=None, stack=None):
    """Replay the trace; yield/emit high-level log lines."""
    op2h = [struct.unpack_from('<I', jt, i * 4)[0] - ENGINE for i in range(256)]
    vm = VM(dbin)
    if trace_ops:
        vm.seed_frame(int(trace_ops[0]['esp'], 16))
    # map opcode index -> actual EFLAGS captured at that opcode's pushfd
    flags_by_op = {}
    if flags:
        for f in flags:
            flags_by_op.setdefault(f['op'], f['eflags'])
    # map opcode index -> captured stack top (32 bytes)
    stack_by_op = {}
    if stack:
        for s in stack:
            stack_by_op[s['op']] = bytes.fromhex(s['stack'])
    lines = []
    end = len(trace_ops) if limit is None else min(len(trace_ops), start + limit)
    for i in range(start, end):
        o = trace_ops[i]
        op = o['op']
        h = op2h[op]
        if h not in HANDLERS:
            print(f"  [unknown handler 0x{h:x} op={op}]")
            continue
        mnem, size, fn = HANDLERS[h]
        # read raw operand bytes directly from the bytecode (esi = ptr past op)
        esi = int(o['esi'], 16)
        oper = dbin[esi - ENGINE:esi - ENGINE + size]
        vm.key = int(o['ebx'], 16)  # rolling key at decode point
        vm.esp = int(o['esp'], 16)  # sync esp to the real execution
        vm.eflags = flags_by_op.get(i)  # actual EFLAGS (None if no pushfd)
        # sync the stack contents to the captured state (covers re-entry frames
        # pushed by native stubs that the replay cannot simulate)
        st = stack_by_op.get(i)
        if st is not None:
            vm.wr(vm.esp, st)

        def log(msg):
            lines.append(f"{i:6d} op={op:3d} {mnem:12s} {msg}")

        fn(vm, op, oper, log)
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default=os.path.join(os.environ.get("TEMP", "."), "emu_trace.json"))
    ap.add_argument("--dbin", default="data/vm_dbin.bin")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--data-only", action="store_true",
                    help="only show DATA/SBOX/slot writes and CALL/RETURN")
    args = ap.parse_args()

    dbin = open(args.dbin, "rb").read()
    jt = dbin[0x5000:0x5400]
    tr = json.load(open(args.trace))
    ops = tr["opcodes"]

    lines = replay(ops, dbin, jt, start=args.start, limit=args.limit)
    for ln in lines:
        if args.data_only:
            if any(k in ln for k in ("SBOX[", "DATA[", "mem8[", "mem16[", "mem32[", "CALL", "RETURN")):
                print(ln)
        else:
            print(ln)


if __name__ == "__main__":
    main()
