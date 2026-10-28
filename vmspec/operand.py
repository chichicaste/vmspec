"""Operand decryption formulas per handler, plus the per-handler key update.

The VM handlers read their operands from the bytecode and decrypt them with a
handler-specific formula over the rolling key ``ebx`` (32-bit). After the
decrypt they update ``ebx`` with a handler-specific width/operation. This
module mirrors both, so the sweep can recover the clear operands and track the
full key (which the 2/4-byte operands and the ``jmp`` target need).

The opcode decrypt (in :mod:`vmspec.sweep`) only touches the low byte; the
handlers here additionally touch the low 16 bits (``push_u16``) or the full
32 bits (``push_u32``).
"""
from __future__ import annotations

__all__ = ["rol8", "ror8", "decrypt_operand", "handler_key_update"]


def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def rol8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _formula_a(al: int, key: int) -> int:
    # 0x00A (ld_data_u16) / 0x08E (st_data_u16)
    al = (al + key) & 0xFF
    al = (-al) & 0xFF
    al ^= 0x65
    al = (al - 0xFB) & 0xFF
    al ^= 0xA1
    al = (al + 1) & 0xFF
    al ^= 0x96
    al = rol8(al, 7)
    al = (al - 0xD5) & 0xFF
    return al


def _formula_b(al: int, key: int) -> int:
    # 0x065 (push_u8) / 0x12B (push_i8)
    al = (al ^ key) & 0xFF
    al = (al - 1) & 0xFF
    al = (~al) & 0xFF
    al = (al - 0x3C) & 0xFF
    al = (-al) & 0xFF
    al ^= 0x88
    al = rol8(al, 1)
    return al


def _formula_c(al: int, key: int) -> int:
    # 0x7F4 (ld_data_u8) / 0xB54 (st_data_u8)
    al = (al ^ key) & 0xFF
    al = ror8(al, 2)
    al = (al + 1) & 0xFF
    al = (-al) & 0xFF
    al = (~al) & 0xFF
    return al


def _formula_d(v16: int, key: int) -> int:
    # 0x038 (push_u16) / 0x81C (push_u16): 16-bit operand, key low 16 bits
    cx = (v16 - (key & 0xFFFF)) & 0xFFFF
    cx = (cx - 0x6C11) & 0xFFFF
    cx = (~cx) & 0xFFFF
    cx = (((cx & 0xFF) << 8) | (cx >> 8)) & 0xFFFF
    cx = (~cx) & 0xFFFF
    return cx


def _formula_e(c: int, key: int) -> int:
    # 0x14D (push_u32): 32-bit operand, full key
    ecx = (c - key) & 0xFFFFFFFF
    ecx = (ecx + 1) & 0xFFFFFFFF
    ecx = (-ecx) & 0xFFFFFFFF
    rot = ((ecx >> 5) | (ecx << 27)) & 0xFFFFFFFF
    ecx = (rot - 1) & 0xFFFFFFFF
    return ecx


# handler offset -> (operand size, decryptor)
_DECRYPTORS: dict[int, tuple[int, object]] = {
    0x00A: (1, _formula_a), 0x08E: (1, _formula_a),
    0x065: (1, _formula_b), 0x12B: (1, _formula_b),
    0x7F4: (1, _formula_c), 0xB54: (1, _formula_c),
    0x038: (2, _formula_d), 0x81C: (2, _formula_d),
    0x14D: (4, _formula_e),
}

# handler offset -> key update (key, operand_clear) -> new key
_KEY_UPDATES: dict[int, object] = {
    0x00A: lambda k, al: (k & ~0xFF) | ((k + al) & 0xFF),
    0x08E: lambda k, al: (k & ~0xFF) | ((k + al) & 0xFF),
    0x065: lambda k, al: (k & ~0xFF) | ((k ^ al) & 0xFF),
    0x12B: lambda k, al: (k & ~0xFF) | ((k ^ al) & 0xFF),
    0x7F4: lambda k, al: (k & ~0xFF) | ((k ^ al) & 0xFF),
    0xB54: lambda k, al: (k & ~0xFF) | ((k ^ al) & 0xFF),
    0x038: lambda k, cx: (k & ~0xFFFF) | ((k - cx) & 0xFFFF),
    0x81C: lambda k, cx: (k & ~0xFFFF) | ((k - cx) & 0xFFFF),
    0x14D: lambda k, ecx: (k - ecx) & 0xFFFFFFFF,
}


def decrypt_operand(handler_off: int, operand: bytes, key: int) -> bytes | None:
    """Decrypt *operand* (raw bytes after the opcode) for *handler_off*.

    ``key`` is the full 32-bit rolling key *after* the dispatcher's opcode
    update. Returns the clear operand bytes, or ``None`` when the handler has
    no operand or is unknown.
    """
    entry = _DECRYPTORS.get(handler_off)
    if entry is None:
        return None
    size, formula = entry
    if len(operand) != size:
        return None
    value = int.from_bytes(operand, "little")
    clear = formula(value, key)
    return clear.to_bytes(size, "little")


def handler_key_update(handler_off: int, operand_clear: bytes, key: int) -> int:
    """Apply the handler's key update; returns the new 32-bit key.

    ``operand_clear`` is the decrypted operand (the value the handler folds
    into ``ebx``). Handlers without an update return ``key`` unchanged.
    """
    update = _KEY_UPDATES.get(handler_off)
    if update is None or not operand_clear:
        return key
    value = int.from_bytes(operand_clear, "little")
    return update(key, value)
