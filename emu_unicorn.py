#!/usr/bin/env python3
"""Unicorn full-trace emulator for the etvm dbin VM.

Loads ``data/vm_dbin.bin`` at its *design* address (0x1AE1000) so all the
0x01AE-prefixed raw pointers resolve with zero relocation, stubs the 4 Win32
imports (WideCharToMultiByte / lstrcpyA / lstrlenA / GetSystemTime), and runs
the real interpreter.  We never reimplement a handler by hand -- Unicorn runs
the actual x86 -- so the rolling-key decode, phase transitions and F1/F2 writes
are all observed, not simulated.

Outputs:
  * opcode trace (JSON)  -- one entry per decoded VM opcode
  * F1/F2 captured from the out-param pointers *and* the dbin slots
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_ERR_FETCH_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
)

# ---------------------------------------------------------------------------
# Design addresses (raw pointers in the dbin are already 0x01AE-based)
# ---------------------------------------------------------------------------
ENGINE     = 0x1AE1000
DBIN_SIZE  = 0x18000
ENTRY      = ENGINE + 0x121        # push 0xd546dcff ; jmp key_entry
DISPATCH   = ENGINE + 0x17C        # interpreter loop entry
FETCH      = ENGINE + 0x198        # mov cl, [esi]      (opcode fetch)
DECODE_JMP = ENGINE + 0x1AE        # jmp [eax*4 + JT]   (dispatch)
JT         = ENGINE + 0x5000
DATA       = ENGINE + 0x4000       # workspace (edi)

# dbin slots for the default F1/F2 (also observed)
SLOT_F1 = ENGINE + 0x1224
SLOT_F2 = ENGINE + 0x1234

# API pointer slots inside the dbin
API_WC2MB   = 0x203C
API_LSTRCPY = 0x2040
API_LSTRLEN = 0x2044
API_SYSTIME = 0x2048

# ---------------------------------------------------------------------------
# Host addresses (free, high, unmapped by the dbin)
# ---------------------------------------------------------------------------
S_WC2MB    = 0x70000000
S_LSTRCPY  = 0x70000100
S_LSTRLEN  = 0x70000200
S_SYSTIME  = 0x70000300

STACK      = 0x20000000
STACK_SIZE = 0x20000
STACK_TOP  = STACK + 0x10000

F1_OUT     = 0x30000000
F2_OUT     = 0x30000100
ECM_ADDR   = 0x30000200
VM_RET     = 0xDEAD0000

# ---------------------------------------------------------------------------
# Handlers that consume inline operand bytes (from keysched.py semantics)
# ---------------------------------------------------------------------------
OPERAND_SIZE = {
    0x00A: 1, 0x065: 1, 0x08E: 1, 0x12B: 1, 0x7F4: 1, 0xB54: 1,
    0x038: 2, 0x81C: 2,
    0x14D: 4,
}

# pushfd addresses (absolute VA) of every flags-pushing handler.  We capture
# the actual EFLAGS here so the decompiler can use the real flags instead of
# re-deriving x86 shift/arith flag semantics by hand.
PUSHFD_ADDRS = {
    0x01AE1088,  # shr16   (0x07f)
    0x01AE10B9,  # and_not16 (0x0b0)
    0x01AE10DC,  # shl16b  (0x0d4)
    0x01AE10FA,  # mul32   (0x0f4)
    0x01AE111B,  # and16   (0x10f)
    0x01AE1170,  # add32   (0x16c)
    0x01AE11BD,  # shrd32  (0x1b5)
    0x01AE11C9,  # add16   (0x1c3)
    0x01AE1270,  # shl16   (0x267)
    0x01AE128C,  # add8    (0x287)
    0x01AE12D9,  # shr16b  (0x2d1)
    0x01AE12E6,  # div64   (0x2df)
    0x01AE12F5,  # and_not32 (0x2ec)
    0x01AE1310,  # shr32   (0x30a)
    0x01AE1816,  # imul32  (0x810)
    0x01AE1BAB,  # shld32  (0xba3)
    0x01AE1BC1,  # shl32   (0xbbb)
}


class VMEmulator:
    def __init__(self, dbin: bytes, systemtime: tuple[int, ...] | None = None,
                 ecm: str = ";0;0;0;0;0;0;0", trace: bool = True,
                 max_insns: int = 50_000_000):
        self.dbin = dbin
        self.systemtime = systemtime or (2017, 1, 6, 7, 0, 53, 39, 2)
        self.ecm = ecm
        self.max_insns = max_insns

        self.opcodes: list[dict] = []
        self.writes: list[dict] = []
        self.api_calls: list[dict] = []
        self.data_writes: list[dict] = []
        self.data_reads: list[dict] = []
        self.flags: list[dict] = []
        self.stack_trace: list[dict] = []
        self.opcode_index = 0
        self.done = False
        self.fault = None

        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # --- memory -------------------------------------------------------
        self.uc.mem_map(ENGINE, DBIN_SIZE, UC_PROT_ALL)
        self.uc.mem_write(ENGINE, dbin)

        self.uc.mem_map(STACK, STACK_SIZE, UC_PROT_ALL)

        # out params + ecm (one 4K page covers F1_OUT..ECM_ADDR+len)
        self.uc.mem_map(F1_OUT & ~0xFFF, 0x3000, UC_PROT_ALL)
        # stubs
        self.uc.mem_map(S_WC2MB & ~0xFFF, 0x2000, UC_PROT_ALL)
        # vm_ret sentinel
        self.uc.mem_map(VM_RET & ~0xFFF, 0x1000, UC_PROT_ALL)
        self.uc.mem_write(VM_RET, b"\xcc")  # int3

        # --- patch API pointers -------------------------------------------
        for off, addr in ((API_WC2MB, S_WC2MB), (API_LSTRCPY, S_LSTRCPY),
                          (API_LSTRLEN, S_LSTRLEN), (API_SYSTIME, S_SYSTIME)):
            self.uc.mem_write(ENGINE + off, struct.pack("<I", addr))

        # --- stub bodies: single ret --------------------------------------
        for s in (S_WC2MB, S_LSTRCPY, S_LSTRLEN, S_SYSTIME):
            self.uc.mem_write(s, b"\xc3")

        # --- ECM wide string ---------------------------------------------
        self.ecm_bytes = ecm.encode("utf-16-le") + b"\x00\x00"
        self.uc.mem_write(ECM_ADDR, self.ecm_bytes)

        # --- stack: push f2, f1, ecm, vm_ret (mirrors etvm.c trampoline) --
        esp = STACK_TOP
        def push(v: int) -> None:
            nonlocal esp
            esp -= 4
            self.uc.mem_write(esp, struct.pack("<I", v))
        push(F2_OUT)
        push(F1_OUT)
        push(ECM_ADDR)
        push(VM_RET)
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EIP, ENTRY)

        # --- hooks --------------------------------------------------------
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)

        # progress bookkeeping
        self.insn_count = 0
        self._last_report = 0

    # -- read helpers ------------------------------------------------------
    def _mem(self, addr: int, n: int) -> bytes:
        return bytes(self.uc.mem_read(addr, n))

    def _u32(self, addr: int) -> int:
        return struct.unpack("<I", self._mem(addr, 4))[0]

    def _reg(self, r) -> int:
        return self.uc.reg_read(r)

    def _arg(self, i: int) -> int:
        esp = self._reg(UC_X86_REG_ESP)
        return self._u32(esp + 4 + i * 4)

    def _stdcall_ret(self, nargs: int, eax: int = 0) -> None:
        esp = self._reg(UC_X86_REG_ESP)
        ret = self._u32(esp)
        self.uc.reg_write(UC_X86_REG_EAX, eax)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4 + nargs * 4)
        self.uc.reg_write(UC_X86_REG_EIP, ret)

    # -- hooks -------------------------------------------------------------
    def _hook_code(self, uc, address, size, user_data):
        self.insn_count += 1
        if address == DECODE_JMP:
            eax = self._reg(UC_X86_REG_EAX)          # decoded opcode
            esi = self._reg(UC_X86_REG_ESI)          # bytecode ptr (past op)
            ebx = self._reg(UC_X86_REG_EBX)          # rolling key
            edi = self._reg(UC_X86_REG_EDI)          # data/workspace
            esp = self._reg(UC_X86_REG_ESP)
            op = eax & 0xFF
            n = OPERAND_SIZE.get(op, 0)
            oper = self._mem(esi, n).hex() if n else ""
            self.opcode_index = len(self.opcodes)
            self.stack_trace.append({
                "op": self.opcode_index,
                "esp": f"0x{esp:08x}",
                "stack": self._mem(esp, 32).hex(),
            })
            self.opcodes.append({
                "op": op, "oper": oper,
                "esi": f"0x{esi:08x}", "ebx": f"0x{ebx:08x}",
                "edi": f"0x{edi:08x}", "esp": f"0x{esp:08x}",
            })
        elif address == S_WC2MB:
            self._wc2mb()
        elif address == S_LSTRCPY:
            self._lstrcpy()
        elif address == S_LSTRLEN:
            self._lstrlen()
        elif address == S_SYSTIME:
            self._get_system_time()
        elif address == VM_RET:
            self.done = True
            uc.emu_stop()
        if address in PUSHFD_ADDRS:
            self.flags.append({
                "op": self.opcode_index,
                "addr": f"0x{address:08x}",
                "eflags": self._reg(UC_X86_REG_EFLAGS),
            })

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        if (SLOT_F1 <= address < SLOT_F1 + 0x10 or
                SLOT_F2 <= address < SLOT_F2 + 0x10 or
                F1_OUT <= address < F1_OUT + 0x20 or
                F2_OUT <= address < F2_OUT + 0x20):
            self.writes.append({
                "addr": f"0x{address:08x}", "size": size,
                "value": value, "n": self.insn_count,
            })
        # data region traffic (S-box / intermediates / workspace)
        if DATA <= address < DATA + 0x200:
            self.data_writes.append({
                "off": address - DATA, "size": size, "value": value,
                "op": self.opcode_index, "n": self.insn_count,
            })

    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        if DATA <= address < DATA + 0x200:
            self.data_reads.append({
                "off": address - DATA, "size": size,
                "op": self.opcode_index, "n": self.insn_count,
            })

    # -- Win32 host functions ----------------------------------------------
    def _wc2mb(self):
        codepage = self._arg(0)
        flags = self._arg(1)
        wstr = self._arg(2)
        cch = self._arg(3)
        mbuf = self._arg(4)
        cb = self._arg(5)
        # read UTF-16LE until NUL (or cch chars if >= 0)
        raw = bytearray()
        p = wstr
        limit = cch if cch >= 0 else 1 << 30
        for _ in range(limit):
            b = self._mem(p, 2)
            if b == b"\x00\x00":
                break
            raw += b
            p += 2
        # ASCII-ish conversion (our ECM is ASCII)
        out = raw.decode("utf-16-le", "replace").encode("latin-1", "replace")
        if mbuf:
            self.uc.mem_write(mbuf, out + b"\x00")
        self.api_calls.append({
            "fn": "WideCharToMultiByte", "cp": codepage, "flags": flags,
            "wstr": f"0x{wstr:08x}", "mbuf": f"0x{mbuf:08x}",
            "in": raw.decode("utf-16-le", "replace"), "out": out.decode("latin-1", "replace"),
        })
        self._stdcall_ret(8, len(out))

    def _lstrcpy(self):
        dst = self._arg(0)
        src = self._arg(1)
        s = bytearray()
        p = src
        while True:
            b = self._mem(p, 1)
            if b == b"\x00":
                break
            s += b
            p += 1
        self.uc.mem_write(dst, bytes(s) + b"\x00")
        self.api_calls.append({"fn": "lstrcpyA", "dst": f"0x{dst:08x}",
                               "s": s.decode("latin-1", "replace")})
        self._stdcall_ret(2, dst)

    def _lstrlen(self):
        s = self._arg(0)
        n = 0
        p = s
        while self._mem(p, 1) != b"\x00":
            n += 1
            p += 1
        self.api_calls.append({"fn": "lstrlenA", "n": n})
        self._stdcall_ret(1, n)

    def _get_system_time(self):
        out = self._arg(0)
        st = self.systemtime
        data = struct.pack("<8H", *st)
        self.uc.mem_write(out, data)
        self.api_calls.append({"fn": "GetSystemTime", "t": list(st)})
        self._stdcall_ret(1, 0)

    # -- run ---------------------------------------------------------------
    def run(self) -> dict:
        t0 = time.time()
        try:
            self.uc.emu_start(ENTRY, 0, timeout=0, count=self.max_insns)
        except UcError as e:
            self.fault = str(e)
        elapsed = time.time() - t0

        f1_out = self._mem(F1_OUT, 16).split(b"\x00")[0].decode("latin-1")
        f2_out = self._mem(F2_OUT, 16).split(b"\x00")[0].decode("latin-1")
        f1_slot = self._mem(SLOT_F1, 16).split(b"\x00")[0].decode("latin-1")
        f2_slot = self._mem(SLOT_F2, 16).split(b"\x00")[0].decode("latin-1")
        sbox = self._mem(DATA, 256).hex()

        return {
            "done": self.done,
            "fault": self.fault,
            "insns": self.insn_count,
            "opcodes": len(self.opcodes),
            "elapsed": elapsed,
            "f1_out": f1_out, "f2_out": f2_out,
            "f1_slot": f1_slot, "f2_slot": f2_slot,
            "sbox_sha": None,
            "sbox": sbox,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbin", default="data/vm_dbin.bin")
    ap.add_argument("--ecm", default=";0;0;0;0;0;0;0")
    ap.add_argument("--year", type=int, default=2017)
    ap.add_argument("--month", type=int, default=1)
    ap.add_argument("--day", type=int, default=7)
    ap.add_argument("--hour", type=int, default=0)
    ap.add_argument("--minute", type=int, default=53)
    ap.add_argument("--second", type=int, default=39)
    ap.add_argument("--ms", type=int, default=2)
    ap.add_argument("--max-insns", type=int, default=50_000_000)
    ap.add_argument("--out", default=None, help="write trace JSON here")
    args = ap.parse_args()

    dbin = open(args.dbin, "rb").read()
    assert len(dbin) == DBIN_SIZE, f"dbin size {len(dbin)} != {DBIN_SIZE}"

    st = (args.year, args.month, 6, args.day, args.hour, args.minute,
          args.second, args.ms)

    emu = VMEmulator(dbin, systemtime=st, ecm=args.ecm,
                     max_insns=args.max_insns)
    result = emu.run()

    print(json.dumps({k: result[k] for k in
                      ("done", "fault", "insns", "opcodes", "elapsed",
                       "f1_out", "f2_out", "f1_slot", "f2_slot")},
                     indent=2))

    print("\n-- API calls --")
    for c in emu.api_calls:
        print(" ", c)

    print("\n-- writes to F1/F2 regions --")
    for w in emu.writes:
        print(" ", w)

    if args.out:
        with open(args.out, "w") as f:
            json.dump({
                "result": result,
                "opcodes": emu.opcodes,
                "writes": emu.writes,
                "api_calls": emu.api_calls,
                "data_writes": emu.data_writes,
                "data_reads": emu.data_reads,
                "flags": emu.flags,
                "stack_trace": emu.stack_trace,
            }, f, indent=1)
        print(f"\n[trace written to {args.out}]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
