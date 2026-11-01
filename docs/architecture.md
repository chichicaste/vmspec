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
| VM detection | `vmspec/config.py` | VM state and dispatcher ranges are supplied by a frontend. Automatic detection is pending; the DBIN-specific frontend lives in private `vmspec-tests`. |
| Handler discovery | Frontend-provided metadata | Finding a dispatcher/table in an unknown binary is pending. DBIN table extraction is kept in the private test repository. |
| DSE | `vmspec/dse.py`, `vmspec/memory.py` | Symbolic branches and ordered events use path-local memory. Tracked 32-bit register writes are captured. Finite in-binary call targets (up to eight) are analyzed inline with symbolic context; unbounded/external calls fail. Above 100 active states, context domains of at most four values are split with guards, capped at 16 variants per path. |
| State graph | `vmspec/state_graph.py` | Preserves memory/register/call effect order, removes unused reads, and merges nodes with their guards. Stores are retained where alias safety is unknown. |
| Operand inference | `vmspec/ir_lowering.py` | Handles multiple contiguous VPC-relative reads of 1, 2, or 4 bytes when each reaches an effect or branch. It records decoder expressions and instruction length in IR. Gapped, overlapping, and ambiguous layouts remain unsupported. |
| VM ISA IR | `vmspec/ir.py` | Implemented as immutable, typed, JSON-serializable Python data. It has ordered blocks, branches, memory reads/writes, calls, context updates and expression trees. |
| SLEIGH backend | `vmspec/sleigh_gen.py` | Consumes only the IR. Emits the supported expression, branch, register-write, and contiguous operand subset; requires 8-bit opcodes, 32-bit addresses/registers, and little-endian effects. Other operand layouts raise an error. |
| Clear-bytecode backend | Not in the public core | The DBIN-specific clear-image path and manual semantics are in private `vmspec-tests`; no IR-based clear-bytecode backend exists yet. |
| Ghidra, CFG, P-Code, C | SLEIGH backend; private test harness | The private regression suite checks one synthetic branch end to end. Full CFG recovery and useful C decompilation remain incomplete. |

The two output paths currently differ: the core analysis pipeline creates IR
and feeds frontend-provided opcode encodings to SLEIGH. The DBIN-specific
clear-image workflow and manual VM interpreter are isolated in private
`vmspec-tests`. A generic clear-bytecode backend remains future work.

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

Apply bounded call-target and context specialization at native transitions,
recover missing handler semantics, and resolve indirect CFG edges before
Ghidra decompilation. Anti-Slop's Parallax VM also needs a dedicated frontend
and 64-bit target support.
