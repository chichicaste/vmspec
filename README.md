# VMSpec — VM deobfuscation via automated SLEIGH spec generation

Independent experimental implementation of the VMSpec architecture, currently validated against a Code Virtualizer-derived VM. Core DSE, state-graph and SLEIGH generation are implemented; automatic semantic/operand recovery and full decompilation are under development.

The sample input is a raw VM blob containing native handlers, a dispatch
table and encrypted bytecode. Its existing clear-image workflow still uses
sample-specific decoding, manual semantics and a reference interpreter.

The `specific` branch adds segmented memory, incremental event attribution,
guard-aware graphs and a [VM ISA IR](docs/isa-ir.md). See the [target
architecture](docs/architecture.md) for the stage-by-stage status and the
[next step](docs/specific-progress.md).

An external VM challenge for future frontend work is indexed in the
[benchmark references](docs/benchmark-references.md).

## Pipeline

1. **Config + handler enumeration** — `tools/gen_config.py` extracts the VM state (VPC/VSP, regions, context) and the 256-entry dispatch table from the blob.
2. **DSE** — `vmspec/dse.py` symbolically executes each handler with angr, recording memory accesses and calls.
3. **State graph** — `vmspec/state_graph.py` merges each handler's DSE state tree into a simplified graph.
4. **VM ISA IR** - `vmspec/ir_lowering.py` converts analysis ASTs into typed expressions and ordered instruction blocks in `vmspec/ir.py`.
5. **SLEIGH generation** - `vmspec/sleigh_gen.py` consumes only the IR. The legacy sample workflow still uses `skeleton.py` and manual `semantics.py`.
6. **Disassembly** — decrypt the bytecode to a clear image (`tools/decrypt_bytecode.py`), package the processor (`tools/package_proc.py`) and disassemble in Ghidra (`analyzeHeadless`).

## Core analysis status

- **Memory model**: path-local recent writes, conservative alias invalidation,
  VMState region classification and explicit readonly ranges.
- **State graph**: ordered events, AST-based read liveness and guarded node
  merging; stores are retained conservatively.
- **SLEIGH**: supported ASTs and internal branches are emitted; unsupported
  semantics fail explicitly instead of becoming zero.
- **Context specialization and operand inference**: still pending.
- **Tests**: `python -m unittest discover -s tests -v`, including optional
  Ghidra compilation and a native-vs-P-Code branch regression.

## Key finding: rolling-key vs decrypt-to-clear

The paper models the opcode rolling key as a SLEIGH **context variable** in the constructor pattern (`byte = C + key - 1`). That is the paper-faithful model, but Ghidra's disassembler **cannot chain fall-through** across an opcode-byte constraint that depends on context — regardless of whether it is an equation, a pinned context (analyzer), or a context field (field-gating). This triple-negative is documented in `docs/fallthrough-critique.md`.

The working path is **decrypt-to-clear**: decrypt the opcode and operand bytes up-front with a flow-sensitive sweep, then emit constant `byte = opcode` patterns, which chain cleanly. Phase 6 uses this path.

## Usage

The raw VM blob is **not** in this repo (it is the analysis input). Fetch it
from the private `vmspec-tests` repo (`data/vm_dbin.bin`). Pass its path as the
first argument to every tool below (shown here as `<blob>`).

```console
# 1. enumerate handlers + build the config
uv run python tools/gen_config.py <blob> data/config.json

# 2. experimental DSE pipeline (fails on unsupported semantics; see progress doc)
uv run python -m vmspec <blob> data/config.json \
    --base-addr 0x1AE1000 --max-steps 100 --out out.slaspec

# 3. decrypt the bytecode to a clear image + clear spec
uv run python tools/decrypt_bytecode.py <blob> data/config.json \
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
│   ├── pipeline.py            #   DSE -> state graph -> IR -> SLEIGH orchestrator
│   ├── ir.py                  #   independent VM ISA IR
│   ├── ir_lowering.py         #   analysis AST -> typed IR conversion
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
│   └── fallthrough-critique.md  # the triple-negative result
└── pyproject.toml
```

The VM blob (`vm_dbin.bin`) and other test artifacts live in the private
`vmspec-tests` repo, not here.

## The bytecode VM

The target is a stack machine with a per-instruction rolling key. Each opcode is encrypted with `cl = ~(ror8((byte - key + 1) & 0xFF, 4) - 0x85)` and the key advances `key -= cl` (low byte). Operands are decrypted per handler (1/2/4 bytes) with handler-specific formulas. The dispatch table maps each of the 256 opcodes to a handler offset. Control flow is a `jmp` (indirect `pc = pop + peek`) and a `ret_native` (VM exit).

## Status

- [x] Repo setup (source-only, GPG-signed commits)
- [x] VM state model + handler enumeration
- [x] DSE harness for handlers
- [x] SLEIGH code generation (deterministic skeleton + P-Code semantics)
- [x] Ghidra disassembly (decrypt-to-clear, phase 6 — both segments, 148 instructions)
- [ ] Complete, semantically validated Ghidra C decompilation

## License

MIT. See `pyproject.toml`.
