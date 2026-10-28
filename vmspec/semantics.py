"""Per-handler P-Code semantics for phase 2 (isa_recovery semantics pass).

Maps each handler offset to its clear-encoding P-Code body.  The semantics
mirror :mod:`vmspec.vm`'s ``handler_effect`` (verified against the engine's
own machine code), expressed over the VM state: the ``VSP`` register, the
``ram`` space (the operand stack + the data region at ``ENGINE + SCR``), and
the instruction's operand fields (``op1``/``op2``/``op4``).

Only the handlers exercised by the bytecode program carry a body; the rest
(including the arithmetic ``add_u32``/``and_not``/``shl_u32``, whose
``pushfd`` EFLAGS computation is not yet modelled) return ``None`` and keep
the ``unimpl`` stub.
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
    # arithmetic (pushfd EFLAGS), jmp (0x304), ret_native (0x7E9): unimpl for now.
    return None
