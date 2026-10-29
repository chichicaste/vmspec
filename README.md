# VMSpec

An implementation of the VMSpec approach ([arXiv:2610.29566](https://arxiv.org/abs/2610.29566)): automatically generate a Ghidra SLEIGH processor specification for an obfuscated virtual machine, then use Ghidra to disassemble and lift the VM bytecode.

The input is a raw VM blob (native handlers + a 256-entry dispatch table + the encrypted bytecode program). The output is a Ghidra processor module that disassembles the decrypted bytecode.

## Pipeline

The implementation follows the paper's stages:

1. **Config + handler enumeration** — `tools/gen_config.py` extracts the VM state (VPC/VSP, regions, context) and the 256-entry dispatch table from the blob.
2. **DSE** — `vmspec/dse.py` symbolically executes each handler with angr, recording memory accesses and calls (custom memory model, no pointer concretization).
3. **State graph** — `vmspec/state_graph.py` merges each handler's DSE state tree into a simplified graph.
4. **SLEIGH generation** — a deterministic skeleton (`vmspec/skeleton.py`) + per-handler P-Code semantics (`vmspec/semantics.py`), compiled with Ghidra's `sleigh` (the isa_recovery two-phase pattern).
5. **Disassembly** — decrypt the bytecode to a clear image (`tools/decrypt_bytecode.py`), package the processor (`tools/package_proc.py`) and disassemble in Ghidra (`analyzeHeadless`).

## Key finding: rolling-key vs decrypt-to-clear

The paper models the opcode rolling key as a SLEIGH **context variable** in the constructor pattern (`byte = C + key - 1`). That is the paper-faithful model, but Ghidra's disassembler **cannot chain fall-through** across an opcode-byte constraint that depends on context — regardless of whether it is an equation, a pinned context (analyzer), or a context field (field-gating). This triple-negative is documented in `docs/fallthrough-critique.md`.

The working path is **decrypt-to-clear**: decrypt the opcode and operand bytes up-front with a flow-sensitive sweep, then emit constant `byte = opcode` patterns, which chain cleanly. Phase 6 uses this path.

## Usage

```console
# 1. enumerate handlers + build the config
uv run python tools/gen_config.py data/vm_dbin.bin data/config.json

# 2. (optional) run the full DSE pipeline -> rolling-key .slaspec
uv run python -m vmspec data/vm_dbin.bin data/config.json \
    --base-addr 0x1AE1000 --max-steps 100 --out out.slaspec

# 3. decrypt the bytecode to a clear image + clear spec
uv run python tools/decrypt_bytecode.py data/vm_dbin.bin data/config.json \
    data/_clear.bin data/_clear.slaspec

# 4. package the clear processor module + install into Ghidra
uv run python tools/package_proc.py data/config.json \
    --ghidra C:\gnu\ghidra_12.2_PUBLIC --install

# 5. disassemble the clear image in Ghidra (headless)
analyzeHeadless <projdir> <projname> -import data/_clear.bin \
    -processor vmspec:LE:32:default -scriptPath ghidra -postScript DumpDisasm.java
```

## Directory

```
vmspec/
├── vmspec/                    # the Python package
│   ├── pipeline.py            #   DSE -> state graph -> SLEIGH orchestrator
│   ├── dse.py                 #   angr-based handler symbolic execution
│   ├── state_graph.py         #   state tree -> merged graph
│   ├── sleigh_gen.py          #   SLEIGH emitter (rolling-key + header/token)
│   ├── skeleton.py            #   deterministic skeleton (isa_recovery phase 1)
│   ├── semantics.py           #   per-handler P-Code bodies (phase 2)
│   ├── sweep.py               #   flow-sensitive (addr, key) bytecode sweep
│   ├── operand.py             #   operand decrypt formulas + key update
│   ├── vm.py                  #   stack-machine interpreter (jmp/ret resolution)
│   ├── config.py / model.py   #   config loading + data model
│   └── memory.py              #   segmented memory model
├── tools/                     # CLI tools
│   ├── gen_config.py          #   phase 1-2: state + handler enumeration
│   ├── decrypt_bytecode.py    #   decrypt to clear image + clear spec
│   ├── gen_skeleton.py        #   emit the deterministic skeleton
│   ├── compile_spec.py        #   compile a .slaspec with sleigh
│   ├── package_proc.py        #   assemble + install the processor module
│   ├── inspect_table.py       #   dump the dispatch table
│   ├── inspect_graph.py       #   dump the state graph
│   ├── fieldgate_spec.py      #   (negative result) field-gating spec
│   └── analyze_context.py     #   (negative result) rolling-key analyzer
├── ghidra/                    # Ghidra post-scripts (Java)
│   ├── DumpDisasm.java        #   dump the disassembly (both segments)
│   ├── DumpDecomp.java        #   dump the decompiled C (documents a limit)
│   └── ApplyContext.java      #   (negative result) pin the rolling key
├── docs/
│   ├── SLEIGH.md              #   Ghidra 12.2 SLEIGH syntax notes
│   └── fallthrough-critique.md  #   the triple-negative result
├── data/                      # analysis input (config.json) + artifacts
└── pyproject.toml
```

## The bytecode VM

The target is a stack machine with a per-instruction rolling key. Each opcode is encrypted with `cl = ~(ror8((byte - key + 1) & 0xFF, 4) - 0x85)` and the key advances `key -= cl` (low byte). Operands are decrypted per handler (1/2/4 bytes) with handler-specific formulas. The dispatch table maps each of the 256 opcodes to a handler offset. Control flow is a `jmp` (indirect `pc = pop + peek`) and a `ret_native` (VM exit).

## Status

- **Phase 6 (disassembly) is complete**: the clear spec disassembles the full bytecode program (both segments, 148 instructions) in Ghidra, with correct variable-length instruction decoding.
- **Decompiler (p-code → C)** is a known limitation: `DecompInterface` fails with `Bad decompile address` on the VM's register/space setup (see `ghidra/DumpDecomp.java`).
- The **rolling-key SLEIGH spec** is a documented negative result; the working path is decrypt-to-clear.

## License

MIT. See `pyproject.toml`.
