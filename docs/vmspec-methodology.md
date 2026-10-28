# VMSpec methodology notes

Condensed from [arXiv:2610.29566](https://arxiv.org/abs/2610.29566) (VMSpec, TU Munich).

## VM model

An obfuscating VM is described by:

- **Code** — the bytecode region; the *virtual program counter* (VPC) points at the
  current instruction.
- **Stack** — optional; modeled by a *VSP* register.
- **VM state regions** — registers / data arrays holding locals.
- **VM context** — decoding state carried across instructions (e.g. an opcode stored in
  the previous instruction, or encryption registers).
- **Global data** — absolute references outside the VM (strings, globals).

The interpreter loop: fetch → decode → dispatch → execute → terminator.

## Pipeline

1. **Preprocessing** — locate VM state and bytecode.
2. **Handler detection** — find opcode→handler boundaries (iterative with analysis).
3. **DSE of handlers** — symbolically execute *all* paths of one handler → state tree.
4. **State graph** — dead-memory elimination + node merge.
5. **Code generation** — state graph → SLEIGH `.slaspec`.
6. **Decompilation** — package spec, load bytecode with the custom processor, decompile.

## Key techniques

- **Custom memory model.** Do *not* concretize symbolic pointers. Emit a fresh symbolic
  variable for every read (except read-only memory); cache recent writes per memory
  region so reads hit the cache when the address is provably within one region. This
  keeps handler semantics complete without assuming pointer values.

- **Function calls.** Never follow calls into external code; record `(call site, target)`
  and emit a call in the generated spec. Massively reduces path count.

- **Context concretization.** For encrypted operands / context-dependent targets, run
  DSE with concrete context+operands. Also used to curb path explosion (concretize once
  active states exceed ~100).

- **State-graph generation.** After DSE, run def-use analysis to drop dead memory stores
  and unused reads (each read produced its own variable, so liveness is direct), then
  merge nodes with equal content+successors.

- **Operand identification.** Sharif et al. heuristic: operands sit at small constant
  offsets from the opcode. Record VPC-relative reads during DSE and apply the heuristic
  *after* state-graph simplification (obfuscators add dead VPC-relative accesses).

- **SLEIGH codegen.** Walk the state graph in topological order; translate each statement
  to its SLEIGH equivalent. Branches on operand values use bit-pattern matching.

- **Post-disassembler pass.** Constant propagation + dead-branch removal (a Ghidra
  analyzer), so the decompiler sees optimized P-Code and doesn't misread decrypted
  indirect gotos as switch tables.

## Reference implementation (from the paper)

- DSE built on **angr** (Python); ~6883 LOC Python + ~1296 LOC Java (Ghidra plugin).
- Obfuscator-specific handler detection for Tigress (`ifnest` dispatch) and
  Code Virtualizer (table dispatch). VMProtect left out (state identification limits).

## Mapping to the target VM

- Bytecode: `vm_dbin.bin` (extracted). Handler table: rolling-key dispatch.
- A partial reference interpreter diverges at an input-dependent step — exactly where
  the VMSpec DSE approach should recover the complete semantics.
- DSE engine: **angr** (chosen). Rationale: VMSpec's core requirement is a memory model
  that does *not* concretize symbolic pointers (the MEMSIGHT-style model); angr supports
  this directly (SimMemory hooks + concretization strategies), has built-in path
  exploration, and is the paper's own engine. Triton's memory model concretizes pointers
  by design and its focus is taint-based concolic analysis, so it would need the custom
  model reimplemented on top of callbacks.
