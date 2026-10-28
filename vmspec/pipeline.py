"""VMSpec pipeline orchestrator.

Ties the package steps together:

1. load the binary into an :class:`angr.Project`;
2. for every handler, run dynamic symbolic execution with
   :func:`vmspec.dse.analyze_handler` to obtain its state tree;
3. collapse each non-empty state tree into a state graph with
   :func:`vmspec.state_graph.build_state_graph`;
4. merge all per-handler graphs into a single synthetic root graph;
5. synthesise the SLEIGH ``.slaspec`` with
   :func:`vmspec.sleigh_gen.generate_sleigh`.

Note on node ids: :func:`build_state_graph` assigns ids from a fresh
counter starting at 0 on every call, so ids from different handler graphs
always overlap.  Before a handler graph is attached to the synthetic root,
its ids are remapped into a disjoint space (see :func:`_remap_ids`).
Handlers whose exploration produced no state tree are skipped with a
warning and do not get an instruction constructor.
"""

from __future__ import annotations

import warnings

import angr

from .dse import analyze_handler
from .model import GraphNode, Handler, VMState
from .sleigh_gen import generate_sleigh
from .state_graph import build_state_graph

__all__ = ["run_pipeline"]


def run_pipeline(
    binary_path: str,
    vm_state: VMState,
    handlers: list[Handler],
    *,
    max_steps: int = 100_000,
    base_addr: int | None = None,
    arch: str = "x86",
) -> str:
    """Run the full VMSpec pipeline and return the generated ``.slaspec``.

    Args:
        binary_path: Path of the binary containing the VM to analyse.
        vm_state: Layout of the virtual machine state (registers, regions,
            context variables).
        handlers: Opcode handlers to analyse.
        max_steps: DSE budget per handler (truncated paths become leaves).
        base_addr: When set, the file is loaded as a raw byte blob (no format
            detection) mapped at this address via angr's ``blob`` backend;
            when ``None`` the usual format-aware loading is used.
        arch: angr architecture name used for raw-blob loading (only relevant
            when ``base_addr`` is set).

    Returns:
        The SLEIGH processor specification as a single string.

    Note:
        Only handlers for which the DSE exploration returned a state tree
        are represented in the spec; the others are skipped with a warning
        so that they do not pull every other handler's nodes into their
        constructor.
    """
    if base_addr is not None:
        project = angr.Project(
            binary_path,
            auto_load_libs=False,
            main_opts={"backend": "blob", "base_addr": base_addr, "arch": arch},
        )
    else:
        project = angr.Project(binary_path, auto_load_libs=False)

    built: list[tuple[Handler, GraphNode]] = []
    for handler in handlers:
        state_root = analyze_handler(project, handler, vm_state, max_steps=max_steps)
        if state_root is None:
            warnings.warn(
                f"handler opcode=0x{handler.opcode:X} entry=0x{handler.entry:X} "
                "produced no DSE states; it is skipped in the generated spec",
                stacklevel=2,
            )
            continue
        built.append((handler, build_state_graph(state_root)))

    root = _merge_handler_graphs(built)
    analyzed = [handler for handler, _ in built]
    return generate_sleigh(root, vm_state, analyzed)


def _merge_handler_graphs(built: list[tuple[Handler, GraphNode]]) -> GraphNode:
    """Combine per-handler state graphs into one synthetic root graph.

    Each handler graph is remapped into a unique id space (offset by the
    cumulative size of all previously merged graphs) and then attached to a
    synthetic root node (``id=0``, ``addr=0``, no ops) whose successors are
    ``(None, handler_root_id)`` pairs.  The root carries the fused
    ``_nodes`` registry that the SLEIGH generator uses to resolve successor
    ids.
    """
    root = GraphNode(id=0, addr=0, ops=[], successors=[])
    merged: dict[int, GraphNode] = {}
    offset = 1  # id 0 stays reserved for the synthetic root.
    for _handler, graph in built:
        remapped = _remap_ids(graph, offset)
        offset += len(remapped)
        root.successors.append((None, graph.id))
        merged.update(remapped)
    root._nodes = {root.id: root, **merged}  # type: ignore[attr-defined]
    return root


def _remap_ids(graph: GraphNode, offset: int) -> dict[int, GraphNode]:
    """Offset every node id of a handler graph into a unique id space.

    ``build_state_graph`` restarts its counter at 0 on every call, so ids of
    different handler graphs collide.  This function adds *offset* to every
    node id and to every successor target (relative references therefore
    stay intact), keeps the graph's own ``_nodes`` registry consistent and
    returns the updated ``id -> GraphNode`` map so the caller can fuse it
    into the synthetic root's registry.
    """
    nodes = dict(getattr(graph, "_nodes", None) or {graph.id: graph})
    id_map: dict[int, int] = {old_id: old_id + offset for old_id in nodes}
    for node in nodes.values():
        node.id = id_map[node.id]
        node.successors = [
            (cond, id_map[target_id]) for cond, target_id in node.successors
        ]
    if hasattr(graph, "_nodes"):
        graph._nodes = {node.id: node for node in nodes.values()}  # type: ignore[attr-defined]
    return {node.id: node for node in nodes.values()}