# VMSpec — VM deobfuscation via automated SLEIGH spec generation

Independent implementation of the **VMSpec** approach
([arXiv:2610.29566](https://arxiv.org/abs/2610.29566), "A Decompiler-based Approach
against Virtual Machine Obfuscation", TU Munich — Kilger, Auer, Andreas).

VMSpec treats an obfuscating VM as an *unknown processor architecture*: it applies
dynamic symbolic execution (DSE) to the VM handlers and automatically synthesizes a
**SLEIGH** processor specification, so an off-the-shelf decompiler (Ghidra) can
disassemble and decompile the VM bytecode as if it were native code.

## Target

A VM-obfuscated binary (interpreter + embedded bytecode). The tooling is
VM-agnostic: it consumes the extracted bytecode (`vm_dbin.bin`) and the
interpreter, and emits a SLEIGH processor spec for decompilation. It is meant
to run against multiple VM-obfuscated samples, not a single target.

## Pipeline

```
1. Preprocessing        → identify VM state (VPC, VSP, state regions, context)
2. Handler detection    → discover opcode → handler boundaries
3. DSE of handlers      → symbolic-execute every path → state tree
4. State graph          → dead-store elimination + node merge → state graph
5. Code generation      → state graph → SLEIGH (.slaspec)
6. Decompilation        → compile spec + Ghidra headless → deobfuscated code
```

## Key techniques (from the paper)

- **Custom memory model** — never concretize symbolic pointers; emit a fresh symbolic
  variable per read (except read-only memory), so handler semantics stay complete.
- **Context concretization** — concretize encrypted operands / context to tame path
  explosion (when active states exceed a threshold).
- **State-graph simplification** — def-use analysis to drop dead memory ops, then merge
  equivalent nodes.
- **Operand identification** — Sharif et al. heuristic: operands sit at small constant
  offsets from the opcode (reads near the VPC).
- **SLEIGH codegen + post-pass** — constant propagation and dead-branch removal so the
  decompiler sees optimized P-Code.

## Status

- [x] Repo setup (source-only, GPG-signed commits)
- [ ] VM state model + handler enumeration
- [ ] DSE harness for handlers
- [ ] SLEIGH code generation
- [ ] Ghidra decompilation + verification vs runtime traces

## License

See `LICENSE`.
