# Implementation progress

The current implementation is an incremental realization of the audit, not a
complete reproduction of the VMSpec paper.

## Architecture

See [architecture.md](architecture.md) for the target pipeline, current implementation status, boundary contracts, and the next operand-inference step.

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
  DBIN-specific frontend metadata is held in the private test repository.
- The core assumes clear opcode bytes by default. A frontend can provide its
  opcode-encoding callback through the Python API.

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

1. Recover native-to-VM register bindings and model native transitions.
   Tracked 32-bit register writes are now lowered; direct in-binary calls are
   inlined only when their target and configured context are concrete. External
   or symbolic calls still fail explicitly.
2. Extend operand inference beyond contiguous VPC-relative reads of 1, 2, or 4
   bytes. Gaps, overlapping reads, and full multi-source taint recovery remain
   unsupported.
3. Extend context specialization beyond solver-unique values. When active
   states exceed 100, unique configured context values are concretized with an
   explicit path guard; ambiguous values remain symbolic.
4. Keep DBIN-specific handlers, operand formulas, the reference VM, and the
   clear-image workflow in private vmspec-tests; replace their manual
   knowledge with inferred semantics in the generic pipeline.
5. Demonstrate complete CFG and C decompilation, then generalize family
   frontends/state detection and expand equivalence tests and benchmarks.

The core backend currently requires 32-bit little-endian targets. Unsupported
ASTs, symbolic access sizes/conditions, missing handler graphs and unresolved
inputs fail explicitly. The experimental DSE path keeps these unsupported
cases explicit. Existing sample configurations should be regenerated with
the sample frontend config to include dispatcher_ranges.

Partial-overlap writes invalidate a whole older cache entry; adjacent writes
are not reconstructed into a larger cached read. Such reads remain symbolic.
Regions without concrete bounds cannot establish disjointness.

The legacy decrypt-to-clear workflow and rolling-context investigation remain
in the private test repository. Neither is evidence that the missing
automated inference or full decompilation has been completed.
