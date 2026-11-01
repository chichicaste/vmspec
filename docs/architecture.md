# Target architecture

The target pipeline follows the separation in this diagram:

```mermaid
flowchart TD
    B[Protected binary] --> D[VM detector<br/>state, VPC/VSP, dispatcher]
    D --> H[Handler discovery]
    H --> X[DSE<br/>segmented memory, calls, branches, specialization]
    X --> G[State graph<br/>read liveness, node merging]
    G --> O[Operand inference<br/>VPC-relative accesses, symbolic decode AST]
    O --> I[VM ISA IR]
    I --> S[SLEIGH backend]
    I --> E[Clear-bytecode backend]
    S --> GH[Ghidra]
    E --> GH
    GH --> C[CFG]
    C --> P[P-Code]
    P --> R[Decompiled C]
```

## Current implementation

| Stage | Current code | Status |
| --- | --- | --- |
| VM detection | `tools/gen_config.py`, `vmspec/config.py` | The config generator has sample-specific addresses and handler names. VM state and dispatcher ranges can be supplied in config. Automatic detection is pending. |
| Handler discovery | `tools/gen_config.py` | Reads a known 256-entry table. Finding a dispatcher/table in an unknown binary is pending. |
| DSE | `vmspec/dse.py`, `vmspec/memory.py` | Symbolic branches and ordered events work with path-local memory. Calls, incomplete paths, and tracked VM-register changes fail explicitly. Context specialization is pending. |
| State graph | `vmspec/state_graph.py` | Removes unused reads and merges nodes with their guards. Stores are retained where alias safety is unknown. |
| Operand inference | `vmspec/ir_lowering.py` | Implemented for one VPC-relative read of 1, 2, or 4 bytes with a consuming write. It records the decoder expression and instruction length in IR. Ambiguous/multiple reads and context inputs remain unsupported. |
| VM ISA IR | `vmspec/ir.py` | Implemented as immutable, typed, JSON-serializable Python data. It has ordered blocks, branches, memory reads/writes, calls, context updates and expression trees. |
| SLEIGH backend | `vmspec/sleigh_gen.py` | Consumes only the IR. Emits the supported expression and branch subset and one contiguous 1/2/4-byte operand after the opcode; requires 8-bit opcodes, 32-bit addresses/registers, and little-endian effects. Other operand layouts raise an error. |
| Clear-bytecode backend | `tools/decrypt_bytecode.py`, `vmspec/skeleton.py` | The existing path uses manual sample semantics and operand lengths. It is not yet an IR backend. |
| Ghidra, CFG, P-Code, C | `ghidra/`, Ghidra tools | The repository has compiled/disassembly experiments and one branch-equivalence fixture. Full CFG recovery and C decompilation have not been demonstrated. |

The two output paths currently differ: the core analysis pipeline creates IR
and feeds the rolling or clear opcode pattern to SLEIGH, while the working
sample clear-image workflow still invokes the manual VM interpreter and
`semantics.py`. Connecting both backends through the same recovered
`Instruction` objects requires operand inference and the remaining register,
call, and control-transfer semantics.

## Boundary contracts

- Detector output is `VMState` plus handler/dispatcher metadata. The current
  config is that contract; it is not an automatic detector.
- DSE output is an ordered state tree. It must either preserve an operation
  and its guard or report the unsupported case.
- State-graph output keeps control-flow guards and removes a read only when
  its value is unused.
- Operand inference should produce an `Operand` with its byte offset, width
  and decoded-value `Expr`, and set `Encoding.length` only when the complete
  length is known. Missing evidence remains `None`.
- The IR is the boundary for every future backend. No angr state, claripy AST,
  or sample handler offset belongs in an `Instruction`.
- Each backend declares its supported IR subset and rejects unsupported
  instructions. A generated listing is not evidence of complete semantics.

## Next implementation step

Generalize operand recovery across paths and multiple reads, and bind the
expression's native context inputs through frontend metadata. Keep ambiguous
layouts unresolved and compare inferred decode expressions with the existing
sample decoder as an oracle. The current basic inference and SLEIGH token path
are covered by `tests/test_ir.py`.
