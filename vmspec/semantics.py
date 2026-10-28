"""Per-handler P-Code semantics for phase 2 (isa_recovery semantics pass).

Maps each handler offset to its clear-encoding P-Code body.  The semantics
mirror :mod:`vmspec.vm`'s ``handler_effect`` (verified against the engine's
own machine code), expressed over the VM state: the ``VSP`` register, the
``ram`` space (the operand stack + the data region at ``ENGINE + SCR``), and
the instruction's operand fields (``op1``/``op2``/``op4``).

Only the handlers exercised by the bytecode program carry a body; the rest
return ``None`` and keep the ``unimpl`` stub.

The ``pushfd`` handlers (``add_u32``/``and_not``/``shl_u32``) compute the x86
EFLAGS word by hand over temporaries — SLEIGH's own flag registers are not
involved (the VM pushes the flags onto its stack, they never reach a native
flags register).  See ``docs/SLEIGH.md`` §13 for the syntax constraints this
respects (1-byte booleans, no ``if`` without ``goto``, XOR-fold parity).
"""

from __future__ import annotations

__all__ = ["handler_pcode", "ENGINE", "SCR"]

ENGINE = 0x1AE1000
SCR = 0x4000          # data region base (dbin + SCR); see vmspec.vm


def _data_addr(index: int) -> str:
    """The absolute data-region address for a constant *index* (op & 0x3C)."""
    return f"0x{ENGINE + SCR + index:X}:4"


def handler_pcode(hoff: int, opcode: int, operand_size: int) -> list[str] | None:
    """Return the clear-encoding P-Code body for a handler, or ``None``.

    ``opcode`` is the (decrypted) opcode index, used for the data-region
    selectors that index by ``op & 0x3C``.  ``operand_size`` is the operand
    length in bytes (0/1/2/4).
    """
    if hoff == 0x14D:  # push_u32: push(operand, 4)
        return ["VSP = VSP - 4;", "*:4 VSP = op4;"]
    if hoff in (0x038, 0x81C):  # push_u16: push(operand, 2)
        return ["VSP = VSP - 2;", "*:2 VSP = op2;"]
    if hoff == 0x065:  # push_u8: push(al, 2) -- zero-extended
        return ["tmp1:1 = op1;", "tmp:2 = zext(tmp1);", "VSP = VSP - 2;", "*:2 VSP = tmp;"]
    if hoff == 0x12B:  # push_i8: push(sign_extend(al), 4)
        return ["tmp1:1 = op1;", "tmp:4 = sext(tmp1);", "VSP = VSP - 4;", "*:4 VSP = tmp;"]
    if hoff == 0x0E2:  # push_sp: push(esp, 4)
        return ["tmp:4 = VSP;", "VSP = VSP - 4;", "*:4 VSP = tmp;"]
    if hoff == 0x176:  # pop: pop(4)
        return ["VSP = VSP + 4;"]
    if hoff == 0x00A:  # ld_data_u16: push(data[al], 2)
        return [
            "tmp1:1 = op1;",
            "tmp:4 = 0x1AE5000:4 + zext(tmp1);",
            "VSP = VSP - 2;",
            "*:2 VSP = *:2 tmp;",
        ]
    if hoff == 0x08E:  # st_data_u16: data[al] = pop(2)
        return [
            "tmp1:1 = op1;",
            "tmp:4 = 0x1AE5000:4 + zext(tmp1);",
            "*:2 tmp = *:2 VSP;",
            "VSP = VSP + 2;",
        ]
    if hoff == 0x02D:  # ld_data_u32: push(data[op&0x3C], 4)
        return [
            "VSP = VSP - 4;",
            f"*:4 VSP = *:4 {_data_addr(opcode & 0x3C)};",
        ]
    if hoff == 0xB49:  # st_data_u32: data[op&0x3C] = pop(4)
        return [
            f"*:4 {_data_addr(opcode & 0x3C)} = *:4 VSP;",
            "VSP = VSP + 4;",
        ]
    if hoff == 0xBB1:  # ld_u16: push([pop(4)], 2)
        return [
            "tmp:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "VSP = VSP - 2;",
            "*:2 VSP = *:2 tmp;",
        ]
    if hoff == 0x276:  # ld_u32: push([pop(4)], 4)
        return [
            "tmp:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "VSP = VSP - 4;",
            "*:4 VSP = *:4 tmp;",
        ]
    if hoff == 0x16C:  # add_u32: [esp] += pop(4); pushfd
        return [
            "tmpb:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "tmpa:4 = *:4 VSP;",
            "tmpt:4 = tmpa + tmpb;",
            "*:4 VSP = tmpt;",
            # x86 EFLAGS of the add (the handler ends with pushfd); the
            # comparison results are 1-byte booleans, zext'ed by hand.
            "cfb:1 = (tmpt < tmpa);",
            "cf:4 = zext(cfb);",
            "zfb:1 = (tmpt == 0);",
            "zf:4 = zext(zfb);",
            "sf:4 = (tmpt >> 31) & 1;",
            "ofx:4 = (tmpa ^ tmpt) & (tmpb ^ tmpt);",
            "of:4 = (ofx >> 31) & 1;",
            "afx:4 = tmpa ^ tmpb ^ tmpt;",
            "af:4 = (afx >> 4) & 1;",
            # PF = even parity of the result's low byte: bit 0 of the XOR
            # fold of the 8 low bits is the odd-parity indicator, invert it.
            "pfold:4 = tmpt ^ (tmpt >> 1) ^ (tmpt >> 2) ^ (tmpt >> 3) ^ (tmpt >> 4) ^ (tmpt >> 5) ^ (tmpt >> 6) ^ (tmpt >> 7);",
            "pf:4 = (pfold & 1) ^ 1;",
            "fl:4 = 0x202:4 | cf | (pf << 2) | (af << 4) | (zf << 6) | (sf << 7) | (of << 11);",
            "VSP = VSP - 4;",
            "*:4 VSP = fl;",
        ]
    if hoff == 0x2EC:  # and_not: [esp] = ~peek() & ~pop(4); pushfd
        return [
            "tmpa:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "a:4 = ~tmpa;",
            "tmpp:4 = *:4 VSP;",
            "t:4 = ~tmpp & ~tmpa;",
            "*:4 VSP = t;",
            # EFLAGS of the and (CF=OF=AF=0; only PF/ZF/SF are set)
            "zfb:1 = (t == 0);",
            "zf:4 = zext(zfb);",
            "sf:4 = (t >> 31) & 1;",
            "pfold:4 = t ^ (t >> 1) ^ (t >> 2) ^ (t >> 3) ^ (t >> 4) ^ (t >> 5) ^ (t >> 6) ^ (t >> 7);",
            "pf:4 = (pfold & 1) ^ 1;",
            "fl:4 = 0x202:4 | (pf << 2) | (zf << 6) | (sf << 7);",
            "VSP = VSP - 4;",
            "*:4 VSP = fl;",
        ]
    if hoff == 0xBBB:  # shl_u32: push(pop(4) << (pop(2)&0x1F), 4); pushfd
        return [
            "eax:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "cx:2 = *:2 VSP;",
            "VSP = VSP + 2;",
            "sh:4 = zext(cx);",
            "sh = sh & 0x1F:4;",
            "r:4 = eax << sh;",
            # CF = the last bit shifted out (bit 32-sh of eax), 0 when sh == 0.
            # Branchless select (if only accepts goto): kn = 32-sh in 1..32,
            # kn>>5 is 1 exactly when sh == 0, and kn&31 keeps the shift
            # itself in range.
            "kn:4 = 0x20:4 - sh;",
            "kcl:4 = kn & 0x1F:4;",
            "kmsk:4 = 0x1:4 ^ (kn >> 5);",
            "cf:4 = ((eax >> kcl) & 1) & kmsk;",
            "VSP = VSP - 4;",
            "*:4 VSP = r;",
            # EFLAGS of the shl (OF/AF not modelled by the VM; CF from above)
            "zfb:1 = (r == 0);",
            "zf:4 = zext(zfb);",
            "sf:4 = (r >> 31) & 1;",
            "pfold:4 = r ^ (r >> 1) ^ (r >> 2) ^ (r >> 3) ^ (r >> 4) ^ (r >> 5) ^ (r >> 6) ^ (r >> 7);",
            "pf:4 = (pfold & 1) ^ 1;",
            "fl:4 = 0x202:4 | cf | (pf << 2) | (zf << 6) | (sf << 7);",
            "VSP = VSP - 4;",
            "*:4 VSP = fl;",
        ]
    if hoff == 0x304:  # jmp: pc = pop(4) + peek(4) (indirect jump)
        return [
            "tv:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "tp:4 = *:4 VSP;",
            "tt:4 = tv + tp;",
            "goto [tt];",
        ]
    if hoff == 0x7E9:  # ret_native: restore native context, native ret
        # The handler is `pop ecx; pop ecx; pop edi; pop ebp; popfd; pop ebx;
        # pop eax; pop edx; pop ebx; pop esi; ret` — ten dword pops (40
        # bytes) off the VM stack, then a native ret whose target is the
        # next stack dword (native code, not VM bytecode; read dynamically).
        return [
            "VSP = VSP + 40;",
            "retpc:4 = *:4 VSP;",
            "VSP = VSP + 4;",
            "return [retpc];",
        ]
    # remaining handlers (not exercised by the bytecode program): unimpl.
    return None
