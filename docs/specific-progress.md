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
- Ordered memory, register, and call effects live in one recorder sequence and
  remain ordered through the state tree, DCE, state graph, IR, and SLEIGH.
  Liveness removes unused reads without reordering surviving effects. The tree
  shares event prefixes across forks and places branch guards after their
  defining loads.
- Context-specialization assumptions are separate metadata in the model and
  IR; they do not become CFG edges or SLEIGH branches.
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

Run from the public repository root:

    .venv\Scripts\python.exe data/external/vmspec-tests/tools/run_core_tests.py

The regression suite is stored in the private companion test repo. It includes
small native x86 handlers, Ghidra SLEIGH compilation, and a pypcode check that
compares branch choice, memory writes, and register results with native angr
execution. Its Ghidra headless check requires a reachable 49-instruction CFG
and minimal C for one Code Virtualizer-derived segment.

The independent IR executor adds a middle comparison point between native
execution and compiled P-Code. Regressions cover branches and repeated register
updates followed by memory writes, including 32-bit wraparound. DSE entry
symbols remain entry snapshots even after a register is written. Arithmetic
evaluation is also compared against Claripy on boundary inputs. Calls,
decode-time context updates, and full-program equivalence remain unsupported
by this executor.

This remains a narrow semantic regression check, not a general equivalence
validator or the paper's benchmark. The second DBIN segment still decompiles
with an unimplemented-handler warning, and no second VM family is validated.

## Remaining work

1. Recover native-to-VM register bindings and model external/native transitions.
   Tracked 32-bit register writes are lowered; finite in-binary call targets
   are analyzed inline with symbolic context. Unbounded or external calls still
   fail explicitly.
2. Extend operand inference beyond contiguous VPC-relative reads of 1, 2, or 4
   bytes. Gaps, overlapping reads, and full multi-source taint recovery remain
   unsupported.
3. Extend context specialization beyond small finite context domains. When
   active states exceed 100, configured domains of up to four values are split
   with explicit path guards (at most 16 variants per path); larger domains
   remain symbolic.
4. Keep DBIN-specific handlers, operand formulas, the reference VM, and the
   clear-image workflow in private vmspec-tests; replace their manual
   knowledge with inferred semantics in the generic pipeline.
5. Validate a second VM family, then generalize dispatcher/VPC/VSP/handler
   discovery and expand equivalence tests and benchmarks.

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

Anti-Slop's Parallax VM is an x86-64 Go service with a QAR cartridge. It needs
a dedicated frontend and wider target support before the current 32-bit
pipeline can analyze it.
