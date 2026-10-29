"""Recovered F1/F2 hash — stage 2 (the substitution core).

The VM's key schedule (see :mod:`vmspec.keysched`) produces a 256-byte S-box.
The *F1/F2 factory passwords* are then computed by native code (the launcher)
as a three-stage pipeline:

    stage 1:  fingerprint + S-box  ->  arg0, arg4 (8-char keys), arg10, arg14
    stage 2:  substitution (this module) -> f1, f2 (8-char keys)
    stage 3:  checksum -> F1, F2 (10 chars = 8-char key + 2-char checksum)

This module implements stage 2, ported from the decompiled ``sub_A9A279``.  The
primitives (the substitution table and the alphabets) are embedded in the engine
image (``vm_dbin.bin`` / ``ettool_dbin.bin``) at fixed offsets:

    =======  ======  =====================================================
    offset   size    content
    =======  ======  =====================================================
    0x149B    28     ``ROT``   rotation alphabet (28 chars)
    0x14B7    32     ``KEY``   output alphabet (32 chars)
    0x14D7   256     ``table`` substitution table (values 0..31)
    0x15D7    32     ``CROCK`` Crocksford base32 alphabet (32 chars)
    =======  ======  =====================================================

The known-good results (for the default fingerprint) are baked into the blob:

    F1 = "KD+4%CQ+NR"   (8-char key "KD+4%CQ" + checksum "NR")
    F2 = "8BSF44M=QY"   (8-char key "8BSF44M=" + checksum "QY")

The fingerprint -> F1/F2 mapping is a one-way hash: stages 1 and 3 are not yet
recovered here (``ROT`` belongs to the not-yet-ported rotation step of stage 1).
"""

from __future__ import annotations

# Offsets of the primitives inside the engine image (vm_dbin.bin).
ROT_OFF = 0x149B
KEY_OFF = 0x14B7
TBL_OFF = 0x14D7
CROCK_OFF = 0x15D7

# F1/F2 result buffers in the engine image.
F1_OFF = 0x1224
F2_OFF = 0x1234


def load_primitives(dbin: bytes) -> tuple[str, str, list[int], str]:
    """Return ``(KEY, ROT, table, CROCK)`` extracted from the engine image."""
    key = dbin[KEY_OFF:KEY_OFF + 32].decode('latin1')
    rot = dbin[ROT_OFF:ROT_OFF + 28].decode('latin1')
    table = list(dbin[TBL_OFF:TBL_OFF + 256])
    crock = dbin[CROCK_OFF:CROCK_OFF + 32].decode('latin1')
    return key, rot, table, crock


def stage2(arg0: str, arg4: str, fingerprint: str, arg10: int, arg14: int,
           prim: tuple[str, str, list[int], str]) -> tuple[str, str]:
    """Stage-2 substitution: ``(arg0, arg4, fingerprint, arg10, arg14) -> (f1, f2)``.

    ``arg0`` / ``arg4`` are 8-char keys produced by stage 1; ``fingerprint`` is
    the (upcased) fingerprint string whose first three characters feed the
    substitution constant; ``arg10`` / ``arg14`` are the stage-1 integers.

    The original code interleaves ``arg0``/``arg4`` into two wide-char arrays and
    walks them *backwards* (byte offset ``arg14`` down to ``0``, step 2), XORing
    the character's index in ``CROCK`` with ``table[sum]`` and emitting a
    character of ``KEY``.  Returns the two 8-char keys ``(f1, f2)``.
    """
    key, _rot, table, crock = prim

    fp = fingerprint.upper()

    # interleave arg0/arg4 (wide chars; see the decompiled sub_A9A279)
    v40 = [arg0[0], arg4[0], arg0[4], arg4[4], arg0[1], arg4[1], arg0[5], arg4[5]]
    v28 = [arg0[2], arg4[2], arg0[6], arg4[6], arg0[3], arg4[3], arg0[7], arg4[7]]

    f1: list[str] = []
    f2: list[str] = []
    var_a4 = 0
    ebx = arg14
    while ebx > -2:
        # index into the wide-char arrays: byte offset ebx -> wide char ebx//2
        idx = ebx // 2
        s = (ord(fp[0]) + ord(fp[1]) + ord(fp[2]) + var_a4 + arg10 + arg14 + 0x20) & 0xFF
        t = table[s]
        i1 = crock.find(v40[idx])
        i2 = crock.find(v28[idx])
        if i1 < 0:
            i1 = 0
        if i2 < 0:
            i2 = 0
        f1.append(key[(i1 ^ t) & 0x1F])
        f2.append(key[(i2 ^ t) & 0x1F])
        var_a4 += 0x20
        ebx -= 2
    return ''.join(f1), ''.join(f2)
