# VMSpec — VM deobfuscation via automated SLEIGH spec generation

Independent experimental implementation of the VMSpec architecture, currently validated against a Code Virtualizer-derived VM. Core DSE, state-graph and SLEIGH generation are implemented; automatic semantic recovery and full decompilation are under development.

Based on Kilger, Auer, and Andreas, [“VMSpec: A Decompiler-based Approach
against Virtual Machine Obfuscation”](https://arxiv.org/html/2610.29566v1) (2026).

The public repository contains the analysis core. Synthetic regression
fixtures and VM-specific test artifacts live in the private companion repo.

The implementation includes segmented memory, ordered effects, separate
specialization assumptions and branch guards, and a [VM ISA IR](docs/isa-ir.md). See the [target
architecture](docs/architecture.md) for the stage-by-stage status and the
[implementation progress](docs/specific-progress.md).

An external VM challenge for future frontend work is indexed in the
[benchmark references](docs/benchmark-references.md).

## Pipeline

1. **Configuration** - `vmspec/config.py` loads frontend-provided VM state and handler metadata; automatic detection is frontend-specific.
2. **DSE** — `vmspec/dse.py` symbolically executes handlers and records ordered effects and branch guards. It explores finite in-binary call targets with symbolic context; unbounded or external calls fail explicitly and require a future call contract or SimProcedure.
3. **State graph** — `vmspec/state_graph.py` merges each handler's DSE state tree into a simplified graph.
4. **VM ISA IR** - `vmspec/ir_lowering.py` converts analysis ASTs into typed expressions and ordered instruction blocks in `vmspec/ir.py`.
5. **SLEIGH generation** - `vmspec/sleigh_gen.py` consumes only the IR. Frontends may provide an opcode-encoding callback; the core assumes clear opcode bytes by default.
6. **Disassembly** - load the generated processor specification into Ghidra. End-to-end CFG and C decompilation remain under development.

## Core analysis status

- **Memory model**: path-local recent writes, conservative alias invalidation,
  VMState region classification and explicit readonly ranges.
- **State graph**: a single ordered effect sequence, AST-based read liveness,
  branch guards separated from specialization assumptions, and guarded node
  merging; liveness removes reads without reordering surviving effects.
- **SLEIGH**: supported ASTs and internal branches are emitted; unsupported
  semantics fail explicitly instead of becoming zero.
- **Operand inference**: multiple contiguous VPC-relative reads of 1, 2, or 4 bytes are supported when their values reach an effect or branch; ambiguous and non-contiguous layouts remain pending.
- **Validation**: the private companion suite compares compiled P-Code with
  native execution for a branching handler's control flow, memory, and register
  results. A Ghidra headless check also requires a reachable CFG and minimal C
  for one Code Virtualizer-derived segment. Other segments and a second VM are
  not yet validated.
- **Tests**: the regression suite lives in the private companion repository
  `data/external/vmspec-tests`; it is not part of this source repo.

## Usage

Install the core dependencies with uv sync. The public CLI accepts a binary
and a JSON frontend configuration:

    uv run python -m vmspec <binary> <frontend-config.json> --out out.slaspec

VM-specific sample data and frontend tooling are maintained separately from
this public analysis core.

## Core files

- vmspec/: VM-agnostic DSE, state graph, ISA IR, and SLEIGH backend.
- tools/compile_spec.py: compile a generated SLEIGH specification.
- tools/inspect_graph.py: inspect a handler graph from frontend-provided metadata.
- docs/architecture.md: target architecture and implementation status.
- docs/specific-progress.md: progress and known limits.
- docs/benchmark-references.md: external VM test candidates.
## License

MIT. See `pyproject.toml`.
