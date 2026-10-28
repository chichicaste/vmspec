#!/usr/bin/env python3
"""Inspect the VM dispatch table (256 x u32: opcode -> handler offset).

Shows the opcode -> handler grouping produced by the dispatcher's
``jmp [eax*4 + table]`` lookup.  Run::

    python tools/inspect_table.py [blob.bin] [config.json]
"""
from __future__ import annotations

import json
import struct
import sys

ENGINE = 0x1AE1000
TAB_OFF = 0x5000  # dispatch table offset in the blob


def main(argv: list[str]) -> int:
    blob_path = argv[0] if len(argv) > 0 else "data/vm_dbin.bin"
    config_path = argv[1] if len(argv) > 1 else "data/config.json"

    dbin = open(blob_path, "rb").read()
    tbl = struct.unpack_from("<256I", dbin, TAB_OFF)
    cfg = json.load(open(config_path, encoding="utf-8"))
    by_entry = {h["entry"]: h for h in cfg["handlers"]}

    # group opcodes by handler offset
    groups: dict[int, list[int]] = {}
    for op in range(256):
        groups.setdefault(tbl[op], []).append(op)

    print(f"{len(groups)} distinct handlers:")
    for off, ops in sorted(groups.items(), key=lambda kv: min(kv[1])):
        h = by_entry.get(off)
        mnem = h["mnemonic"] if h else "??"
        rng = ", ".join(f"0x{o:02X}" for o in ops)
        print(f"  {mnem} (off 0x{off - ENGINE:X}): {rng}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
