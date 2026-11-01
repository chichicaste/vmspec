# VM ISA IR

The analysis/backend boundary is now:

```text
angr / claripy -> State Graph -> ir_lowering -> ISA -> SLEIGH
                                             |
                                             +-> other consumers
```

`vmspec.ir` contains only immutable Python dataclasses, tuples and scalars.
It imports neither angr nor claripy. `vmspec.ir_lowering` owns the conversion
from analysis objects. `vmspec.sleigh_gen.generate_sleigh` accepts only an
`ISA`; it cannot render an analysis AST or a State Graph.

## Instruction representation

| Member | Meaning |
| --- | --- |
| `opcode` | Logical opcode index |
| `encoding` | Expression matched by the raw opcode byte; optional total byte length |
| `operands` | Operand name, byte offset, encoded byte size and decoded value expression |
| `blocks`, `entry` | Ordered effects and guarded edges; entry block id |
| `reads`, `writes` | Derived memory-effect views over the blocks |
| `stack_effect` | Optional summary expression; it is not an additional executable effect |
| `expressions` | All unique expressions used by the instruction |
| `branches`, `calls` | Derived views of block edges and ordered call effects |
| `context_updates` | Ordered decode-time context assignments |

Blocks are authoritative for execution order. Derived lists are useful for
inspection but must not be executed as separate instruction phases: a store,
call and second store retain their original order in `block.operations`.
Branch targets are local block ids, not native instruction addresses.
Branches are considered in order; a block with no selected edge exits the
instruction. `source_address` and call `site` are optional provenance.

Expressions use named operations such as `add`, `slt`, `lshr`, `ashr`,
`extract`, `concat` and `ite`, with explicit bit widths. Arithmetic
bitvectors wrap at that width. Boolean values are distinct from one-bit
bitvectors. Extract's `value` is the least significant bit offset.
Signedness is encoded in the operation, not inferred from a variable name.
Register, temporary, context and operand references occupy distinct IR
namespaces. Memory effects retain their byte size and byte order.

Validation rejects incompatible widths, missing blocks, duplicate temporary
definitions, uses before a definition and definitions that do not dominate
all incoming paths. These checks happen before invoking a backend.

## Unknown is not zero

The current analysis does not yet recover operand encodings or stack effects.
It sets `operands=None`, `encoding.length=None` and `stack_effect=None`.
An empty operand tuple means known absence of operands; it is distinct from
unknown. The SLEIGH backend labels unresolved encodings as opcode-only and
rejects known operand encodings it cannot yet lower.

The existing sample's rolling opcode formula is translated into IR encoding
expressions and context updates. It remains sample knowledge, not inferred
knowledge. The SLEIGH backend consumes that formula rather than reconstructing
it from the logical opcode. Dispatch aliases retain separate opcode/context
updates while their block semantics are equivalent.

## Python API

```python
from dataclasses import asdict
import json

from vmspec.config import load_config
from vmspec.pipeline import recover_isa
from vmspec.sleigh_gen import generate_sleigh

config = load_config("config.json")
isa = recover_isa(
    "handler.bin", config.vm_state, config.handlers,
    base_addr=config.base_addr, arch=config.arch,
    dispatch_table=config.dispatch_table, mode="clear",
)
spec = generate_sleigh(isa)
snapshot = json.dumps(asdict(isa), indent=2)
```

`run_pipeline(...)` keeps its existing signature and returns SLEIGH, but now
calls `recover_isa(...)` first. Direct callers of the former
`generate_sleigh(graph, vm_state, handlers, ...)` API must migrate to
`generate_sleigh(isa)`. Existing analyzed handler graphs can be converted
with `lower_isa([(handler, graph), ...], vm_state, ...)`; node ids are not
mutated or merged across handlers.

The JSON snapshot contains authoritative blocks and expressions. The derived
views need not be duplicated in storage. There is no JSON import API or
versioned interchange format yet.

## Scope and verification

SLEIGH is the implemented backend. A debugger, general IR emulator, LLVM
backend and general equivalence validator are not implemented by this change.
The existing compiled-P-Code branch comparison remains a regression test.

The current encoding model represents an eight-bit opcode, and SLEIGH still
targets 32-bit little-endian memory, the existing register layout and the
sample's eight-bit `key` context field. Native register effects, operand
inference and specialization remain separate work.

Tests verify JSON-compatible IR without analysis objects, deterministic
temporary names, effect order, dispatch aliases, typing and dominance.
A subprocess without site-packages builds an ISA and emits SLEIGH. Ghidra
tests compile both clear and rolling encodings, and the native/P-Code branch
comparison passes through the new IR boundary.
