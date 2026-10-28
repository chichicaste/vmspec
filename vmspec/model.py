"""Core data model for VMSpec.

Defines the structures produced by the DSE-based analysis of VM handlers:
the virtual state layout (:class:`VMState`, :class:`Region`,
:class:`RegionKind`), handler metadata (:class:`Handler`), the symbolic
state tree (:class:`StateNode`, :class:`MemAccess`, :class:`Call`) and the
merged state graph (:class:`GraphNode`) consumed by the SLEIGH generator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "RegionKind",
    "Region",
    "VMState",
    "Handler",
    "MemAccess",
    "Call",
    "StateNode",
    "GraphNode",
]


class RegionKind(str, Enum):
    """Classification of a VM state region."""

    CODE = "code"
    STACK = "stack"
    STATE = "state"
    CONTEXT = "context"
    GLOBAL = "global"


@dataclass
class Region:
    """A named region of the VM state (code, stack, locals, ...)."""

    name: str
    kind: RegionKind
    base: int | None = None
    size: int | None = None


@dataclass
class VMState:
    """Layout of the virtual machine state discovered during preprocessing.

    Attributes:
        vpc: Name of the register holding the virtual program counter.
        vsp: Name of the register holding the virtual stack pointer, if any.
        regions: State regions modeled as SLEIGH registers/spaces.
        context: Identifiers of extra context variables carried across
            instructions (decoding state, encryption registers, ...).
        entry: Host address of the VM entry point, when known.
        bytecode: Raw contents of the bytecode region, when available.
    """

    vpc: str
    vsp: str | None = None
    regions: list[Region] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    entry: int | None = None
    bytecode: bytes | None = None


@dataclass
class Handler:
    """Metadata discovered for a single opcode handler."""

    opcode: int
    entry: int
    end: int
    mnemonic: str = ""


@dataclass
class MemAccess:
    """A symbolic memory access recorded during DSE.

    Attributes:
        kind: ``"read"`` or ``"write"``.
        addr: Opaque symbolic address expression.
        value: Opaque symbolic value expression.  For a *read* this is the
            fresh variable produced by the access (each read yields its own
            variable under the VMSpec memory model); for a *write* it is the
            stored value.
        size: Number of bytes accessed.
    """

    kind: str
    addr: object
    value: object
    size: int

    def __post_init__(self) -> None:
        if self.kind not in ("read", "write"):
            raise ValueError(
                f"MemAccess.kind must be 'read' or 'write', got {self.kind!r}"
            )
        if self.size <= 0:
            raise ValueError(f"MemAccess.size must be positive, got {self.size!r}")


@dataclass
class Call:
    """A recorded ``(site, target)`` VM call.

    External code is never followed during DSE; the pair is kept so the
    generated spec can emit the call.
    """

    site: int
    target: object


@dataclass
class StateNode:
    """A node in the per-handler DSE state tree.

    ``mem_ops`` is the linear sequence of symbolic memory accesses executed
    on the way into the successors; ``calls`` are the external calls
    recorded at this state; ``cond`` is the symbolic guard selecting this
    node's branch (evaluated when the node is entered); ``successors`` are
    the DSE states that follow.
    """

    addr: int
    mem_ops: list[MemAccess] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    successors: list["StateNode"] = field(default_factory=list)
    cond: object | None = None


@dataclass
class GraphNode:
    """A node in the merged state graph (state tree after simplification).

    Attributes:
        id: Stable integer assigned by
            :func:`vmspec.state_graph.build_state_graph`.
        addr: VM (or host) address this node corresponds to.
        ops: Simplified operations to translate to P-Code (``MemAccess`` /
            ``Call`` instances, plus explicit op names for arithmetic).
        successors: ``(edge_condition, target_node_id)`` pairs.  The
            condition is the guard of the target state, or ``None`` for an
            unconditional fall-through.
    """

    id: int
    addr: int
    ops: list = field(default_factory=list)
    successors: list[tuple[object, int]] = field(default_factory=list)