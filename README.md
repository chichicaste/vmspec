# VMSpec — VM deobfuscation via automated SLEIGH spec generation

Independent experimental implementation of the VMSpec architecture, currently validated against a Code Virtualizer-derived VM. Core DSE, state-graph and SLEIGH generation are implemented; automatic semantic/operand recovery and full decompilation are under development.

The DBIN-specific code, private data, and analysis tools are kept in the
nested private repository `data/external/vmspec-tests`. The public repository
contains the VM-agnostic analysis core and synthetic regression fixtures.

The `specific` branch adds segmented memory, incremental event attribution,
guard-aware graphs and a [VM ISA IR](docs/isa-ir.md). See the [target
architecture](docs/architecture.md) for the stage-by-stage status and the
[next step](docs/specific-progress.md).

An external VM challenge for future frontend work is indexed in the
[benchmark references](docs/benchmark-references.md).

## Pipeline

1. **Configuration** - `vmspec/config.py` loads frontend-provided VM state and handler metadata; automatic detection is frontend-specific.
2. **DSE** — `vmspec/dse.py` symbolically executes each handler with angr, recording memory accesses and calls.
3. **State graph** — `vmspec/state_graph.py` merges each handler's DSE state tree into a simplified graph.
4. **VM ISA IR** - `vmspec/ir_lowering.py` converts analysis ASTs into typed expressions and ordered instruction blocks in `vmspec/ir.py`.
5. **SLEIGH generation** - `vmspec/sleigh_gen.py` consumes only the IR. Frontends may provide an opcode-encoding callback; the core assumes clear opcode bytes by default.
6. **Disassembly** - load the generated processor specification into Ghidra. End-to-end CFG and C decompilation remain under development.

## Core analysis status

- **Memory model**: path-local recent writes, conservative alias invalidation,
  VMState region classification and explicit readonly ranges.
- **State graph**: ordered events, AST-based read liveness and guarded node
  merging; stores are retained conservatively.
- **SLEIGH**: supported ASTs and internal branches are emitted; unsupported
  semantics fail explicitly instead of becoming zero.
- **Operand inference**: one contiguous VPC-relative operand is supported; multi-read layouts and native context bindings remain pending.
- **Tests**: `python -m unittest discover -s tests -v`, including optional
  Ghidra compilation and a native-vs-P-Code branch regression.

## Usage

Install the core dependencies with uv sync. The public CLI accepts a binary
and a JSON frontend configuration:

    uv run python -m vmspec <binary> <frontend-config.json> --out out.slaspec

The DBIN sample workflow, test data, and Ghidra scripts live in the private
repository at data/external/vmspec-tests in the local checkout.

## Core files

- vmspec/: VM-agnostic DSE, state graph, ISA IR, and SLEIGH backend.
- tools/compile_spec.py: compile a generated SLEIGH specification.
- tools/inspect_graph.py: inspect a handler graph from frontend-provided metadata.
- docs/architecture.md: target architecture and implementation status.
- docs/specific-progress.md: progress and known limits.
- docs/benchmark-references.md: external VM test candidates.
## License

MIT. See `pyproject.toml`.
