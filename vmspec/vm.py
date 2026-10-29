"""VM stack machine for resolving the ``jmp`` (0x304) target.

The dispatcher's ``jmp`` computes ``pc = pop(4) + peek(4)`` from the operand
stack, so following it requires the stack semantics of every handler on the
path. This module mirrors the reconstructed interpreter's stack machine: a
sparse runtime-write map (the stack + data writes) layered over the raw blob
(the data region and code), plus the push/pop/peek helpers and the per-handler
stack effect for the handlers exercised by the bytecode program.

The handler semantics here are verified against the engine's own machine code
(the dispatch table maps op -> engine-relative handler offset, so the handler
bodies live inside the blob itself):

* dispatcher (engine+0x198): fetch/decrypt the opcode, ``sub bl, cl`` (low
  byte of the rolling key only), then ``jmp dword ptr [eax*4 + TAB]``;
* epilogue (engine+0x193): the ``jmp`` handler is ``pop esi`` + ``jmp 0x193``
  where ``mov ebx, esi`` (the popped value IS the new rolling key) and
  ``add esi, [esp]`` (pc = popped value + peek);
* the data region base is ``edi = 0x1AE5000 = ENGINE + 0x4000`` (the
  ``mov edi, imm32`` at engine+0x18E), so ``st/ld_data_*`` address
  ``[edi + idx]`` — note the raw blob already carries DISP at ``dbin[0x4010]``
  (slot 0x10) and the unpacker's KEY reloc at ``dbin[0x4014]`` (slot 0x14);
* the arithmetic handlers terminate with ``pushfd`` — they push the x86
  EFLAGS of the operation, not a zero dword.
"""
from __future__ import annotations

from vmspec.operand import decrypt_operand, handler_key_update
from vmspec.sweep import decrypt

ENGINE = 0x1AE1000
SCR = 0x4000          # data region offset (dbin + SCR): the engine prologue
                      # loads edi = 0x1AE5000 = ENGINE + 0x4000 (mov edi at
                      # engine+0x18E) and st/ld_data_* address [edi + idx].
SP0 = 0x7287E0        # initial stack pointer
DISP = 0x16E0000      # dispatcher displacement
KEY = 0x407575        # initial rolling key

# initial stack frame (16 dwords at SP0), captured from the runtime
FRAME = [DISP, 0, 0xFFFFFFFF, 0xEFFADC, 0x246, 0x72C0E0, 0x1240, 0x1C,
         0x72C0E0, 0x72C19E, KEY, 0xD546DCFF, 0x575F84, 0x727E78, 0, 0]

# handler offset -> operand length (bytes following the encrypted opcode)
OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

# handler offsets that terminate a path (no computed target / program end)
_RET_NATIVE = 0x7E9


class VM:
    """The VM's operand stack + data region (sparse writes over the blob)."""

    def __init__(self, dbin: bytes, esp: int = SP0):
        self.dbin = dbin
        self.esp = esp & 0xFFFFFFFF
        self.mem: dict[int, int] = {}  # byte addr -> byte (sparse runtime writes)
        # The rolling-key register (ebx). Only the ``jmp`` handler writes it
        # from a stack value (``pop esi; mov ebx, esi`` at the epilogue); the
        # operand-driven updates live in vmspec.operand.handler_key_update.
        self.ebx = 0

    def wr(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.mem[(addr + i) & 0xFFFFFFFF] = b

    def rd(self, addr: int, n: int) -> bytes:
        out = bytearray()
        for i in range(n):
            a = (addr + i) & 0xFFFFFFFF
            if a in self.mem:
                out.append(self.mem[a])
            else:
                off = a - ENGINE
                if 0 <= off < len(self.dbin):
                    out.append(self.dbin[off])
                else:
                    out.append(0)
        return bytes(out)

    def push(self, v: int, n: int) -> None:
        self.esp = (self.esp - n) & 0xFFFFFFFF
        self.wr(self.esp, v.to_bytes(n, "little"))

    def pop(self, n: int) -> int:
        v = int.from_bytes(self.rd(self.esp, n), "little")
        self.esp = (self.esp + n) & 0xFFFFFFFF
        return v

    def peek(self, k: int = 0, n: int = 4) -> int:
        return int.from_bytes(self.rd((self.esp + k) & 0xFFFFFFFF, n), "little")


def _scr_addr(index: int) -> int:
    """SCR data address: ENGINE + SCR + index."""
    return ENGINE + SCR + index


def _eflags_add(a: int, b: int) -> int:
    """x86 EFLAGS after ``add`` (the 0x16C handler ends with ``pushfd``)."""
    r = (a + b) & 0xFFFFFFFF
    cf = 1 if a + b > 0xFFFFFFFF else 0
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    of = 1 if ((a ^ r) & (b ^ r)) & 0x80000000 else 0
    pf = 1 if bin(r & 0xFF).count("1") % 2 == 0 else 0
    af = 1 if ((a ^ b ^ r) & 0x10) else 0
    # 0x202 = the standing bits (reserved bit 1 + IF)
    return 0x202 | cf | (pf << 2) | (af << 4) | (zf << 6) | (sf << 7) | (of << 11)


def _eflags_logic(r: int) -> int:
    """x86 EFLAGS after ``and`` (CF=OF=0; the 0x2EC handler ends with ``pushfd``)."""
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = 1 if bin(r & 0xFF).count("1") % 2 == 0 else 0
    return 0x202 | (pf << 2) | (zf << 6) | (sf << 7)


def _eflags_shift(r: int, cf: int) -> int:
    """x86 EFLAGS after ``shl`` (the 0xBBB handler ends with ``pushfd``)."""
    zf = 1 if r == 0 else 0
    sf = (r >> 31) & 1
    pf = 1 if bin(r & 0xFF).count("1") % 2 == 0 else 0
    return 0x202 | cf | (pf << 2) | (zf << 6) | (sf << 7)


def handler_effect(hoff: int, op: int, operand_clear: bytes | None, vm: VM) -> int | None:
    """Apply a handler's stack effect.

    Returns the computed ``jmp`` target (0x304), ``None`` for the native
    return (0x7E9), or the value is ignored for fall-through handlers (the
    caller advances to the next instruction).
    """
    if hoff == 0x304:  # jmp: pc = pop(4) + peek(4); ebx = popped value
        v = vm.pop(4)
        pk = vm.peek()
        vm.ebx = v  # the epilogue (engine+0x193) does `mov ebx, esi`
        return (v + pk) & 0xFFFFFFFF
    if hoff == 0x7E9:  # ret_native
        return None

    if hoff == 0xB49:  # st_data_u32: data[op&0x3C] = pop(4)
        vm.wr(_scr_addr(op & 0x3C), vm.pop(4).to_bytes(4, "little"))
    elif hoff == 0x14D:  # push_u32: push(ecx, 4)
        vm.push(int.from_bytes(operand_clear or b"\x00" * 4, "little"), 4)
    elif hoff == 0x16C:  # add_u32: [esp] += pop(4); pushfd
        v4 = vm.pop(4)
        a = vm.peek()
        t = (a + v4) & 0xFFFFFFFF
        vm.wr(vm.esp, t.to_bytes(4, "little"))
        vm.push(_eflags_add(a, v4), 4)
    elif hoff == 0x065:  # push_u8: push(al, 2)
        vm.push(operand_clear[0] if operand_clear else 0, 2)
    elif hoff == 0x00A:  # ld_data_u16: push(data[al], 2)
        al = operand_clear[0] if operand_clear else 0
        vm.push(int.from_bytes(vm.rd(_scr_addr(al), 2), "little"), 2)
    elif hoff == 0xBBB:  # shl_u32: push(pop(4) << (pop(2)&0x1F), 4); pushfd
        eax = vm.pop(4)
        cx = vm.pop(2)
        sh = cx & 0x1F
        r = (eax << sh) & 0xFFFFFFFF
        vm.push(r, 4)
        cf = (eax >> (32 - sh)) & 1 if 1 <= sh <= 31 else 0
        vm.push(_eflags_shift(r, cf), 4)
    elif hoff == 0x08E:  # st_data_u16: data[al] = pop(2)
        al = operand_clear[0] if operand_clear else 0
        vm.wr(_scr_addr(al), vm.pop(2).to_bytes(2, "little"))
    elif hoff == 0x12B:  # push_i8: push(sign_extend, 4)
        v = operand_clear[0] if operand_clear else 0
        vm.push((v - 256 if v & 0x80 else v) & 0xFFFFFFFF, 4)
    elif hoff == 0x0E2:  # push_sp: push(esp, 4)
        vm.push(vm.esp, 4)
    elif hoff == 0xBB1:  # ld_u16: push([pop(4)], 2)
        a = vm.pop(4)
        vm.push(int.from_bytes(vm.rd(a, 2), "little"), 2)
    elif hoff == 0x02D:  # ld_data_u32: push(data[op&0x3C], 4)
        vm.push(int.from_bytes(vm.rd(_scr_addr(op & 0x3C), 4), "little"), 4)
    elif hoff == 0x276:  # ld_u32: push([pop(4)], 4)
        a = vm.pop(4)
        vm.push(int.from_bytes(vm.rd(a, 4), "little"), 4)
    elif hoff == 0x2EC:  # and_not: not [esp]; [esp] &= ~pop(4); pushfd
        a = (~vm.pop(4)) & 0xFFFFFFFF
        t = (~vm.peek()) & 0xFFFFFFFF
        vm.wr(vm.esp, t.to_bytes(4, "little"))
        t = (vm.peek() & a) & 0xFFFFFFFF
        vm.wr(vm.esp, t.to_bytes(4, "little"))
        vm.push(_eflags_logic(t), 4)
    # other handlers: no stack effect (or not exercised by this program)
    return -1  # fall-through sentinel


def run(
    dbin: bytes,
    tbl: list[int],
    entry: int,
    initial_key: int,
    *,
    max_steps: int = 100_000,
):
    """Execute the VM (fetch + decrypt + handler) and yield the trace.

    Yields ``(pc, opcode, key_before, operand_clear, operand_len)`` tuples and
    resolves ``jmp`` targets via the stack.  ``pc`` is the absolute bytecode
    address; ``operand_clear`` is the decrypted operand bytes (or ``None``) and
    ``operand_len`` its length.  Stops at the native return (0x7E9) or the step
    bound.
    """
    vm = VM(dbin)
    # initial stack frame (16 dwords at SP0), captured from the runtime
    for i, v in enumerate(FRAME):
        vm.wr(SP0 + i * 4, v.to_bytes(4, "little"))
    pc = entry
    key = initial_key
    for _ in range(max_steps):
        byte = dbin[pc - ENGINE]
        op = decrypt(byte, key & 0xFF)
        key_before = key
        # dispatcher update: `sub bl, cl` (engine+0x1A9) — only the low byte
        # of the rolling key changes; the high 3 bytes are never touched here.
        key = (key & ~0xFF) | ((key & 0xFF) - op & 0xFF)

        hoff = tbl[op] - ENGINE
        olen = OPERAND_LEN.get(hoff, 0)
        operand = dbin[pc + 1 - ENGINE:pc + 1 + olen - ENGINE]
        clear = decrypt_operand(hoff, operand, key)
        key = handler_key_update(hoff, clear or b"", key)

        yield pc, op, key_before, clear, olen

        target = handler_effect(hoff, op, clear, vm)
        if target is None:  # ret_native
            return
        if target == -1:  # fall-through
            pc += 1 + olen
        else:  # jmp target: the popped value is also the new rolling key
            pc = target
            key = vm.ebx
