"""Discovery for unoptimized x86 Tigress interpolation dispatchers.

Recognizes table structure and native data flow, never opcode semantics.
Other Tigress dispatch modes must fail rather than invent metadata.
"""
from collections import Counter
from dataclasses import dataclass

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ..model import Handler, Region, RegionKind, VMState


@dataclass(frozen=True)
class FrameSlot:
    base: str
    offset: int
    size: int


@dataclass(frozen=True)
class Discovery:
    vm_state: VMState
    handlers: tuple[Handler, ...]
    slots: dict[str, FrameSlot]
    table_address: int
    native_bits: int


def _slot(insn, operand):
    if operand.type != X86_OP_MEM or operand.mem.index:
        return None
    base = insn.reg_name(operand.mem.base)
    if base not in {"rbp", "ebp"}:
        return None
    return FrameSlot(base, operand.mem.disp, operand.size)


def discover(project) -> Discovery:
    """Recover a unique interpolation VM or raise with an explicit reason.

    Frame slots are normalized metadata, not native register names. Consumers
    must support these bindings before attempting handler DSE.
    """
    if project.arch.name not in {"X86", "AMD64"}:
        raise ValueError("Tigress interpolation discovery requires x86")
    obj = project.loader.main_object
    instructions = {}
    for section in obj.sections:
        if section.is_executable:
            data = project.loader.memory.load(section.vaddr, section.memsize)
            instructions.update((i.address, i) for i in project.arch.capstone.disasm(data, section.vaddr))
    width = project.arch.bytes
    stride = width * 2
    tables = []
    for section in obj.sections:
        if not section.vaddr or not section.is_readable or section.is_executable or section.memsize < stride * 4:
            continue
        data = project.loader.memory.load(section.vaddr, section.memsize)
        run = []
        for offset in range(0, len(data) - stride + 1, stride):
            opcode = int.from_bytes(data[offset:offset + width], "little")
            target = int.from_bytes(data[offset + width:offset + stride], "little")
            valid = opcode <= 255 and target in instructions
            if run and (not valid or opcode <= run[-1][0]):
                if len(run) >= 4:
                    tables.append((section.vaddr + offset - len(run) * stride, tuple(run)))
                run = []
            if valid:
                run.append((opcode, target))
        if len(run) >= 4:
            tables.append((section.vaddr + offset + stride - len(run) * stride, tuple(run)))

    found = []
    ordered = sorted(instructions.values(), key=lambda i: i.address)
    positions = {i.address: n for n, i in enumerate(ordered)}
    for table, entries in tables:
        targets = sorted({target for _, target in entries})
        jumps = Counter()
        for index, target in enumerate(targets):
            end = targets[index + 1] if index + 1 < len(targets) else target + 256
            for i in ordered[positions[target]:]:
                if i.address >= end:
                    break
                if i.mnemonic == "jmp" and i.operands[0].type == X86_OP_IMM:
                    destination = i.operands[0].imm
                    if destination < targets[0]:
                        jumps[destination] += 1
        if not jumps:
            continue
        dispatcher, count = jumps.most_common(1)[0]
        if count < 3 or dispatcher not in positions:
            continue
        body = [i for i in ordered if dispatcher <= i.address < targets[0]]
        if not any(o.type == X86_OP_IMM and o.imm == table for i in body for o in i.operands):
            continue
        if len(body) < 2 or body[-1].mnemonic != "jmp" or body[-1].operands[0].type != X86_OP_REG:
            continue
        first, fetch = body[:2]
        if first.mnemonic != "mov" or len(first.operands) != 2:
            continue
        vpc = _slot(first, first.operands[1])
        if (vpc is None or first.operands[0].type != X86_OP_REG or
                fetch.mnemonic != "movzx" or fetch.operands[1].type != X86_OP_MEM or
                fetch.operands[1].size != 1 or fetch.operands[1].mem.base != first.operands[0].reg):
            continue
        candidates = Counter()
        for target in targets:
            start = positions[target]
            for i, following in zip(ordered[start:start + 24], ordered[start + 1:start + 25]):
                if i.mnemonic != "mov" or len(i.operands) != 2 or i.operands[0].type != X86_OP_REG:
                    continue
                slot = _slot(i, i.operands[1])
                if slot is None or slot == vpc or slot.size != width:
                    continue
                if any(o.type == X86_OP_MEM and o.mem.base == i.operands[0].reg for o in following.operands):
                    candidates[slot] += 1
        ranked = candidates.most_common()
        if not ranked or ranked[0][1] < 3 or (len(ranked) > 1 and ranked[0][1] == ranked[1][1]):
            continue
        regions = [Region(s.name, RegionKind.CODE if s.is_executable else
                          RegionKind.GLOBAL if s.is_writable else RegionKind.READONLY,
                          s.vaddr, s.memsize) for s in obj.sections if s.vaddr and s.is_readable and s.memsize]
        state = VMState("vpc", "vsp", regions=regions,
                        dispatcher_ranges=[(dispatcher, targets[0] - dispatcher)])
        found.append(Discovery(state, tuple(Handler(op, target, dispatcher) for op, target in entries),
                               {"vpc": vpc, "vsp": ranked[0][0]}, table, project.arch.bits))
    if len(found) != 1:
        raise ValueError(f"expected one supported Tigress interpolation VM, found {len(found)}")
    return found[0]
