#!/usr/bin/env python3
"""Inspect the merged state graph of one VM handler (DSE -> state graph).

Useful to see what the SLEIGH generator consumes: the nodes' memory ops
(``MemAccess`` / ``Call``) and the successor edges (unconditional fall-through
vs conditional branch).  Run::

    python tools/inspect_graph.py [config.json] [blob.bin] [mnemonic|opcode]
"""
from __future__ import annotations

import sys

import angr

from vmspec.config import load_config
from vmspec.dse import analyze_handler
from vmspec.state_graph import build_state_graph


def _cond_desc(cond) -> str:
    if cond is None:
        return "None"
    if hasattr(cond, "op"):
        return f"{cond.op} {list(cond.args) if hasattr(cond, 'args') else ''}"
    return repr(cond)


def main(argv: list[str]) -> int:
    config_path = argv[0] if len(argv) > 0 else "data/config.json"
    blob_path = argv[1] if len(argv) > 1 else "data/vm_dbin.bin"
    target = argv[2] if len(argv) > 2 else "pop"

    cfg = load_config(config_path)
    project = angr.Project(
        blob_path, auto_load_libs=False,
        main_opts={"backend": "blob", "base_addr": cfg.base_addr, "arch": cfg.arch},
    )

    matched = [
        h for h in cfg.handlers
        if h.mnemonic == target or str(h.opcode) == target or f"0x{h.opcode:X}" == target
    ]
    if not matched:
        print(f"no handler matching {target!r}")
        return 1
    handler = matched[0]

    state_root = analyze_handler(project, handler, cfg.vm_state, max_steps=100)
    if state_root is None:
        print(f"{handler.mnemonic}: no DSE states")
        return 1
    graph = build_state_graph(state_root)
    nodes = getattr(graph, "_nodes", {graph.id: graph})

    print(f"=== {handler.mnemonic} (op 0x{handler.opcode:X}) {len(nodes)} nodes ===")
    for nid in sorted(nodes):
        node = nodes[nid]
        ops = [type(o).__name__ for o in node.ops]
        print(f"  n{nid} addr=0x{node.addr:X} ops={ops}")
        for cond, tid in node.successors:
            print(f"      -> n{tid}  cond={_cond_desc(cond)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
