"""Recovered VM key schedule (the 256-byte S-box generation).

The VM program (3 phases, ~1091 steps) is *not* the F1/F2 hash itself; it
generates a 256-byte S-box in the data region (``ENGINE + 0x4000``) that the
native launcher later combines with the fingerprint to produce F1/F2.  This
module is a clean Python rewrite of that key schedule, lifted from the
machine-code-verified emulator (``_fullsim.py``) with the VM decrypt/dispatch
overhead removed.

The rolling key is threaded through the schedule (``key -= op`` per opcode, plus
per-handler updates), so the schedule cannot be reduced to a stateless formula;
it is expressed as the same stack machine, but as a single self-contained
function.
"""
from __future__ import annotations

ENGINE = 0x1AE1000
DATA = 0x1AE5000            # data region (engine + 0x4000)
DISP = 0x16E0000
KEY = 0x407575
SP0 = 0x7287E0
M = 0xFFFFFFFF


def _ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF if n & 7 else x


def _rol8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF if n & 7 else x


def _flags_add(a: int, b: int) -> int:
    r = (a + b) & M
    cf = 1 if (a + b) > M else 0
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    of = 1 if ((a ^ r) & (b ^ r) & 0x80000000) else 0
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    af = 1 if ((a ^ b ^ r) & 0x10) else 0
    return 0x202 | cf | (pf << 2) | (af << 4) | (zf << 6) | (sf << 7) | (of << 11)


def _flags_logic(r: int) -> int:
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    return 0x202 | (pf << 2) | (zf << 6) | (sf << 7)


def _flags_shift(r: int, cf: int) -> int:
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = bin(r & 0xFF).count('1') & 1 ^ 1
    return 0x202 | cf | (pf << 2) | (zf << 6) | (sf << 7)


def _parse_reentry(dbin: bytes, off: int) -> tuple[int, int, int] | None:
    """Parse a re-entry stub: (key, stub_push, enterN).

    (a) ``C8 imm16 imm8; 68 stub_push; E9 -> key-entry (68 key; E9 -> prologue)``
    (b) ``68 key`` directly.
    """
    if off + 4 > len(dbin):
        return None
    if dbin[off] == 0xC8:
        enterN = dbin[off + 1] | (dbin[off + 2] << 8)
        j = off + 4
        if j + 5 > len(dbin) or dbin[j] != 0x68:
            return None
        stub_push = int.from_bytes(dbin[j + 1:j + 5], 'little')
        e = j + 5
        if e + 5 > len(dbin) or dbin[e] != 0xE9:
            return None
        keyentry = (e + 5 + int.from_bytes(dbin[e + 1:e + 5], 'little', signed=True)) & M
        if keyentry + 5 > len(dbin) or dbin[keyentry] != 0x68:
            return None
        key = int.from_bytes(dbin[keyentry + 1:keyentry + 5], 'little')
        return key, stub_push, enterN
    if dbin[off] == 0x68:
        return int.from_bytes(dbin[off + 1:off + 5], 'little'), 0, 0
    return None


class _VM:
    """The stack machine state (sparse memory + esp)."""

    def __init__(self, dbin: bytes, frame: list[int], key: int):
        self.dbin = dbin
        self.mem: dict[int, int] = {}
        self.esp = SP0
        self.key = key
        for i in range(0x100):
            self.mem[DATA + i] = dbin[0x4000 + i]
        self.wr32(DATA + 0x14, key)
        for i, v in enumerate(frame):
            self.wr32(SP0 + i * 4, v)

    def rd(self, a: int, n: int) -> bytes:
        out = bytearray()
        for i in range(n):
            x = (a + i) & M
            if x in self.mem:
                out.append(self.mem[x])
            else:
                off = x - ENGINE
                out.append(self.dbin[off] if 0 <= off < len(self.dbin) else 0)
        return bytes(out)

    def wr(self, a: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.mem[(a + i) & M] = b

    def rd16(self, a: int) -> int:
        return int.from_bytes(self.rd(a, 2), 'little')

    def rd32(self, a: int) -> int:
        return int.from_bytes(self.rd(a, 4), 'little')

    def wr16(self, a: int, v: int) -> None:
        self.wr(a, v.to_bytes(2, 'little'))

    def wr32(self, a: int, v: int) -> None:
        self.wr(a, v.to_bytes(4, 'little'))

    def push(self, v: int, n: int) -> None:
        self.esp = (self.esp - n) & M
        self.wr(self.esp, v.to_bytes(n, 'little'))

    def pop(self, n: int) -> int:
        v = int.from_bytes(self.rd(self.esp, n), 'little')
        self.esp = (self.esp + n) & M
        return v

    def peek(self, k: int = 0, n: int = 4) -> int:
        return int.from_bytes(self.rd((self.esp + k) & M, n), 'little')


def key_schedule(dbin: bytes, tbl: list[int], verbose: bool = False) -> bytes:
    """Run the VM's key schedule and return the 256-byte S-box (data region)."""
    frame = [DISP, 0, 0xFFFFFFFF, 0xEFFADC, 0x246, 0x72C0E0, 0x1240, 0x1C,
             0x72C0E0, 0x72C19E, KEY, 0xD546DCFF, 0x575F84, 0x727E78, 0, 0]
    vm = _VM(dbin, frame, KEY)
    host_ebp = 0xEFFADC

    def decrypt_opcode(c: int) -> int:
        bl = vm.key & 0xFF
        cl = (c - bl) & 0xFF
        cl = (cl + 1) & 0xFF
        cl = _ror8(cl, 4)
        cl = (cl - 0x85) & 0xFF
        cl = (~cl) & 0xFF
        vm.key = (vm.key & ~0xFF) | ((bl - cl) & 0xFF)
        return cl

    pc = ENGINE + 0x6575
    steps = 0
    # stop when the pc leaves the engine (the final native return)
    while steps < 1200 and ENGINE <= pc < ENGINE + len(dbin):
        cur_pc = pc
        op = decrypt_opcode(dbin[pc - ENGINE])
        off = tbl[op] - ENGINE
        pc += 1
        steps += 1
        if verbose:
            print(f'  step {steps:5d} pc=+0x{cur_pc - ENGINE:05x} op=0x{op:02x} h=0x{off:03x} key=0x{vm.key:08x} esp=0x{vm.esp:08x}')

        if off == 0x00A:
            al = (dbin[pc - ENGINE] + vm.key) & 0xFF; al = (-al) & 0xFF; al ^= 0x65
            al = (al - 0xFB) & 0xFF; al ^= 0xA1; al = (al + 1) & 0xFF
            al ^= 0x96; al = _rol8(al, 7); al = (al - 0xD5) & 0xFF
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) + al) & 0xFF)
            vm.push(vm.rd16(DATA + al), 2)
        elif off == 0x02D:
            vm.push(vm.rd32(DATA + (op & 0x3C)), 4)
        elif off == 0x065:
            al = (dbin[pc - ENGINE] ^ vm.key) & 0xFF; al = (al - 1) & 0xFF; al = (~al) & 0xFF
            al = (al - 0x3C) & 0xFF; al = (-al) & 0xFF; al ^= 0x88; al = _rol8(al, 1)
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ al) & 0xFF)
            vm.push(al, 2)
        elif off == 0x07F:
            dx = vm.pop(2); cx = vm.pop(2)
            vm.push((dx >> (cx & 0x1F)) & 0xFFFF, 2); vm.push(_flags_logic(0), 4)
        elif off == 0x08E:
            al = (dbin[pc - ENGINE] + vm.key) & 0xFF; al = (-al) & 0xFF; al ^= 0x65
            al = (al - 0xFB) & 0xFF; al ^= 0xA1; al = (al + 1) & 0xFF
            al ^= 0x96; al = _rol8(al, 7); al = (al - 0xD5) & 0xFF
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) + al) & 0xFF)
            vm.wr16(DATA + al, vm.pop(2))
        elif off == 0x0E2:
            vm.push(vm.esp, 4)
        elif off == 0x12B:
            cl = (dbin[pc - ENGINE] ^ vm.key) & 0xFF; cl = (cl - 1) & 0xFF; cl = (~cl) & 0xFF
            cl = (cl - 0x3C) & 0xFF; cl = (-cl) & 0xFF; cl ^= 0x88; cl = _rol8(cl, 1)
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ cl) & 0xFF)
            vm.push((cl - 256) & M if cl & 0x80 else cl, 4)
        elif off == 0x14D:
            c4 = vm.rd32(pc); pc += 4
            ecx = (c4 - vm.key) & M; ecx = (ecx + 1) & M; ecx = (-ecx) & M
            ecx = ((ecx >> 5) | (ecx << 27)) & M; ecx = (ecx - 1) & M
            vm.key = (vm.key - ecx) & M
            vm.push(ecx, 4)
        elif off in (0x163, 0x27F, 0x0EB):
            a = vm.pop(4); v = vm.pop(4); vm.wr32(a, v)
        elif off == 0x16C:
            v4 = vm.pop(4); a = vm.peek()
            vm.wr32(vm.esp, (a + v4) & M)
            vm.push(_flags_add(a, v4), 4)
        elif off == 0x176:
            vm.pop(4)
        elif off == 0x1C3:
            v4 = vm.pop(2); a = vm.peek(0, 2)
            vm.wr16(vm.esp, (a + v4) & 0xFFFF)
            vm.push(_flags_add(a, v4), 4)
        elif off == 0x267:
            dx = vm.pop(2); cx = vm.pop(2)
            vm.push((dx << (cx & 0x1F)) & 0xFFFF, 2); vm.push(_flags_logic(0), 4)
        elif off == 0x276:
            a = vm.pop(4); vm.push(vm.rd32(a), 4)
        elif off == 0x287:
            v4 = vm.pop(2); a = vm.peek(0, 1)
            vm.wr(vm.esp, ((a + v4) & 0xFF).to_bytes(1, 'little'))
            vm.push(_flags_add(a, v4), 4)
        elif off == 0x292:
            vm.esp = vm.pop(4)
        elif off == 0x2D1:
            dx = vm.pop(2); cx = vm.pop(2)
            dl = (dx & 0xFF) >> (cx & 0x1F)
            vm.push((dx & 0xFF00) | dl, 2); vm.push(_flags_logic(0), 4)
        elif off == 0x2EC:
            a = (~vm.pop(4)) & M
            t = (~vm.peek()) & M
            vm.wr32(vm.esp, t)
            t = vm.peek() & a
            vm.wr32(vm.esp, t)
            vm.push(_flags_logic(t), 4)
        elif off == 0x30A:
            eax = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
            vm.push((eax >> sh) & M, 4)
            vm.push(_flags_shift(eax >> sh, eax & 1), 4)
        elif off == 0x304:
            v = vm.pop(4); pk = vm.peek()
            vm.key = v
            pc = (v + pk) & M
        elif off == 0x038:
            v16 = vm.rd16(pc); pc += 2
            cx = (v16 - (vm.key & 0xFFFF)) & 0xFFFF; cx = (cx - 0x6C11) & 0xFFFF
            cx = (~cx) & 0xFFFF; cx = (((cx & 0xFF) << 8) | (cx >> 8)) & 0xFFFF; cx = (~cx) & 0xFFFF
            vm.key = (vm.key & ~0xFFFF) | (((vm.key & 0xFFFF) - cx) & 0xFFFF)
            vm.push(cx, 2)
        elif off in (0x058, 0x0C9, 0x2A5):
            a = vm.pop(4); vm.push(vm.rd(a, 1)[0], 2)
        elif off == 0x0B0:
            t = (~vm.peek()) & M; vm.wr32(vm.esp, t)
            cx = vm.pop(2)
            v16 = vm.peek(0, 2) & cx
            vm.wr16(vm.esp, v16); vm.push(0, 4)
        elif off == 0x0BF:
            vm.push(vm.esp & 0xFFFF, 2)
        elif off == 0x0D4:
            dx = vm.pop(2); cx = vm.pop(2)
            dl = (dx & 0xFF) << (cx & 0x1F) & 0xFF
            vm.push((dx & 0xFF00) | dl, 2); vm.push(0, 4)
        elif off == 0x0F4:
            edx = vm.pop(4); eax = vm.pop(4)
            p = eax * edx
            vm.push(p & M, 4); vm.push((p >> 32) & M, 4); vm.push(0, 4)
        elif off == 0x10F:
            ax = vm.pop(2); dx = vm.pop(2)
            al8 = (~ax & dx) & 0xFF
            vm.push((ax & 0xFF00) | al8, 2); vm.push(0, 4)
        elif off == 0x1B5:
            eax = vm.pop(4); edx = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
            r = ((eax >> sh) | (edx << (32 - sh))) & M if sh else eax
            vm.push(r, 4); vm.push(0, 4)
        elif off in (0x29A, 0x2B1, 0xB88):
            a = vm.pop(4); v4 = vm.pop(2); vm.wr(a, (v4 & 0xFF).to_bytes(1, 'little'))
        elif off == 0x2BC:
            a = vm.pop(4); vm.push(vm.rd32(a), 4)
        elif off == 0x2DF:
            edx = vm.pop(4); eax = vm.pop(4); ecx = vm.pop(4)
            if ecx == 0:
                raise ZeroDivisionError
            dd = (edx << 32) | eax
            vm.push((dd // ecx) & M, 4); vm.push((dd % ecx) & M, 4); vm.push(0, 4)
        elif off in (0x2FB, 0xB7E, 0xB99):
            a = vm.pop(4); v16 = vm.pop(2); vm.wr16(a, v16)
        elif off == 0x7F4:
            al = (dbin[pc - ENGINE] ^ vm.key) & 0xFF; al = _ror8(al, 2); al = (al + 1) & 0xFF
            al = (-al) & 0xFF; al = (~al) & 0xFF
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ al) & 0xFF)
            vm.push(vm.rd(DATA + al, 1)[0], 2)
        elif off == 0x810:
            edx = vm.pop(4); eax = vm.pop(4)
            p = ((eax ^ 0x80000000) - 0x80000000) * ((edx ^ 0x80000000) - 0x80000000)
            vm.push(p & M, 4); vm.push((p >> 32) & M, 4); vm.push(0, 4)
        elif off == 0x81C:
            v16 = vm.rd16(pc); pc += 2
            ax = (v16 - (vm.key & 0xFFFF)) & 0xFFFF; ax = (ax - 0x6C11) & 0xFFFF
            ax = (~ax) & 0xFFFF; ax = (((ax & 0xFF) << 8) | (ax >> 8)) & 0xFFFF; ax = (~ax) & 0xFFFF
            vm.key = (vm.key & ~0xFFFF) | (((vm.key & 0xFFFF) - ax) & 0xFFFF)
            vm.push(ax, 4)
        elif off == 0xB40:
            a = vm.pop(4); vm.push(vm.rd16(a), 2)
        elif off == 0xB54:
            al = (dbin[pc - ENGINE] ^ vm.key) & 0xFF; al = _ror8(al, 2); al = (al + 1) & 0xFF
            al = (-al) & 0xFF; al = (~al) & 0xFF
            pc += 1
            vm.key = (vm.key & ~0xFF) | (((vm.key & 0xFF) ^ al) & 0xFF)
            vm.wr(DATA + al, (vm.pop(2) & 0xFF).to_bytes(1, 'little'))
        elif off == 0xB92:
            v4 = vm.pop(2); vm.esp = (vm.esp & 0xFFFF0000) | v4
        elif off == 0xBA3:
            eax = vm.pop(4); edx = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
            r = ((eax << sh) | (edx >> (32 - sh))) & M if sh else eax
            vm.push(r, 4); vm.push(0, 4)
        elif off == 0x7E9:  # ret_native: re-enter via the native stub
            for _ in range(10):
                vm.pop(4)
            ra = vm.pop(4)
            re = _parse_reentry(dbin, ra - ENGINE) if ENGINE <= ra < ENGINE + len(dbin) else None
            if re:
                key2, stub_push, enterN = re
                old_ebp = host_ebp
                vm.esp = (vm.esp - 4) & M
                vm.wr32(vm.esp, old_ebp)
                host_ebp = vm.esp
                vm.esp = (vm.esp - enterN) & M
                vm.esp = (vm.esp - 4) & M
                vm.wr32(vm.esp, stub_push)
                vm.esp = (vm.esp - 4) & M
                vm.wr32(vm.esp, key2)
                regs = [DISP, 0, 0xFFFFFFFF, host_ebp, 0x246, 0x72C0E0, 0x1240, 0x1C,
                        0x72C0E0, 0x72C19E]
                for i in range(9, -1, -1):
                    vm.esp = (vm.esp - 4) & M
                    vm.wr32(vm.esp, regs[i])
                vm.key = key2
                pc = (key2 + DISP) & M
            else:
                pc = ra
        elif off == 0xB49:
            vm.wr32(DATA + (op & 0x3C), vm.pop(4))
        elif off == 0xBB1:
            a = vm.pop(4); vm.push(vm.rd16(a), 2)
        elif off == 0xBBB:
            eax = vm.pop(4); cx = vm.pop(2); sh = cx & 0x1F
            r = (eax << sh) & M
            vm.push(r, 4)
            vm.push(_flags_shift(r, (eax >> (sh - 1)) & 1 if sh else 0), 4)
        else:
            raise ValueError(f'unknown handler off=0x{off:X}')

    return bytes(vm.mem.get(DATA + i, 0) for i in range(0x100))
