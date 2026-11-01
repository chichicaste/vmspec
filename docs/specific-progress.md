# Work on the specific branch

This branch is an incremental implementation of the audit, not a complete
reproduction of the VMSpec paper.

## Implemented and checked

- [VM ISA IR](isa-ir.md) now separates analysis from the SLEIGH backend.
  Ordered blocks, typed expressions, operand/stack metadata and decode context
  updates are independent of angr/claripy. `recover_isa()` exposes the result.

- DSE receives VMState regions. Cached writes are path-local, classified by
  region, and reused only when the solver proves a unique byte offset.
  Disjoint regions retain independent writes; possible overlaps invalidate
  older entries. Unknown pointers use the same conservative alias check.
- Symbolic reads and writes do not choose pointer values. Mutable image
  memory is symbolic unless a prior write supplies its value. A readonly
  region may supply an image value only at a uniquely determined address.
- Ordered memory/call events live in angr histories. The tree shares event
  prefixes across forks and places outgoing guards after their defining loads.
- Read liveness traverses symbolic ASTs. Forwarded reads do not redefine
  previous values. Node merging includes edge guards and operation order.
  Stores are retained conservatively pending sound alias-aware dead-store
  elimination.
- SLEIGH bodies retain internal control flow using local P-Code labels.
  Arithmetic, signed comparisons/shifts, byte extraction/extension,
  concatenation, reversal and conditional expressions have explicit lowering.
  Unknown inputs and unsupported operators raise instead of becoming zero.
- Dispatcher ranges belong to configuration, not to a constant in core DSE.
  The sample-specific config generator supplies its known range.
- The CLI accepts --mode clear or --mode rolling. The clear mode in the core
  matches opcode bytes; it does not normalize encrypted operands.

## Validation

Run from the repository root:

    .venv\Scripts\python.exe -m unittest discover -s tests -v

The tests use synthetic states and a small native x86 handler. No private
blob is required. Ghidra integration tests compile the emitted specifications;
they skip explicitly if the compiler is unavailable. A pypcode-based test
executes the compiled branch fixture for four inputs and compares its memory
result with native x86 execution in angr. Its deliberately small test
interpreter rejects any operation outside that fixture.

This is a narrow semantic regression check, not a general equivalence
validator or the paper's benchmark.

## Remaining work

1. Recover native-to-VM register bindings and lower register updates, VPC
   transfers, calls and native transitions. The current DSE rejects calls,
   incomplete paths and changes to tracked VM registers.
2. Infer operand encodings and decryption expressions into the existing IR.
   The current core emitter still assumes one opcode byte.
3. Implement context concretization/specialization with explicit permitted
   context, rather than arbitrary state concretization.
4. Replace the sample-specific reference path: semantics.py, operand.py,
   vm.py and the clear-image utility still contain manual knowledge.
5. Demonstrate complete CFG and C decompilation, then generalize family
   frontends/state detection and expand equivalence tests and benchmarks.

The core backend currently requires 32-bit little-endian targets. Unsupported
ASTs, symbolic access sizes/conditions, missing handler graphs and unresolved
inputs fail explicitly. This intentionally makes the experimental DSE path
stricter than main. Existing sample configurations should be regenerated with
tools/gen_config.py to include dispatcher_ranges.

Partial-overlap writes invalidate a whole older cache entry; adjacent writes
are not reconstructed into a larger cached read. Such reads remain symbolic.
Regions without concrete bounds cannot establish disjointness.

The legacy decrypt-to-clear workflow and rolling-context investigation remain
available. Neither is evidence that the missing automated inference or full
decompilation has been completed.
