# SLEIGH notes for VMSpec (Ghidra 12.2)

Reference notes for the SLEIGH code generation step of VMSpec
([arXiv:2610.29566](https://arxiv.org/abs/2610.29566)). The paper describes the
SLEIGH generation conceptually (§5.1 *Context Analysis*, §5.4 *SLEIGH
Specification Generation*), but its inline examples (Figure 1, Figure 4) are
simplified and do not match the SLEIGH grammar accepted by Ghidra 12.2. This
document records the syntax that **actually compiles** on `support/sleigh.bat`
12.2, the differences from the paper, and the parts the paper leaves implicit.

---

## 1. Header

```sleigh
define endian=little;      # no spaces around '='
define alignment=1;
```

There is **no `version 2.0` statement** in a `.slaspec`. Comments start with
`#` (C-style `//` is rejected: `extraneous input '//'`).

## 2. Address spaces

Modern syntax (12.2):

```sleigh
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
```

The paper-era form `define space ram ( "ram", 0, 4 )` no longer parses
(`expecting SEMI, unexpected token: '('`).

## 3. Registers

Modern bracket-list syntax:

```sleigh
define register offset=0x0    size=4 [ VPC VSP ];      # VPC at +0, VSP at +4
define register offset=0x2000 size=4 contextreg;        # the context register
```

The `belongsTo( context )` / `define register "X" ( "X" )` form is gone.

## 4. Tokens and fields

```sleigh
define token instr(8)
  byte=(0,7)      # bits 0..7 INCLUSIVE = 8 bits
;
```

**Field ranges are inclusive** `(low, high)`. So `(0,7)` is 8 bits; `(0,8)` is
9 bits and is rejected (`Field 'byte' high must be less than token size`).

## 5. Context

```sleigh
define register offset=0x2000 size=4 contextreg;
define context contextreg
  key=(0,7)        # 8-bit rolling key
  ;
```

- The context register size must be a **multiple of 4 bytes** (underlying
  storage is Java `int`).
- Context fields should **not span a 4-byte boundary**.
- `noflow` attribute: prevents the context change from flowing to the next
  instruction (we do *not* use it — the rolling key is persistent).

## 6. Constructor

```
:name <display> is <pattern> [ <disassembly-action> ] { <semantics> }
```

`is` is **mandatory** (omitting it yields `expecting RES_IS, unexpected EOF`).
The `<display>` section is optional. An empty `{ }` semantics is legal (the
constructor becomes a NOP).

```sleigh
:ld_data_u16 is byte = 0x2 + key - 1 [ key = key - 0x64; ] {
}
```

To mark a constructor as **unimplemented** (an `UNIMPLEMENTED` p-code op instead
of a NOP), use the `unimpl` keyword *in place of* the `{ ... }` block — no
braces, no semicolon; it follows the optional disassembly action:

```sleigh
:op_00 is byte = 0x48 + key - 1 [ key = key - 0x00; globalset(inst_next, key); ] unimpl
```

Writing `unimpl;` inside a `{ }` block is rejected
(`no viable alternative on SEMI`). This is how the deterministic skeleton
(isa_recovery phase 1) stubs every constructor.

## 7. Bit-pattern (constraint) expressions

A constraint is `<symbol> = <expression>` — the **left-hand side must be a
single family symbol** (a field or context variable), not an arbitrary
expression. Operators on the right-hand side:

| Operation | Syntax |
|---|---|
| add / sub / mul / div | `+ - * /` |
| left / right shift | `<< >>` |
| bitwise xor | `^` |
| bitwise and / or (constraint) | `$and` / `$or` |
| pattern combining and / or | `&` / `|` |

Key gotchas:

- `&` and `|` are the **pattern combiners** (logical and/or across constraints),
  **not** bitwise. Bitwise and/or inside a constraint must use `$and`/`$or`.
- `~` (bitwise negation) is **not viable in the constraint** (`no viable
  alternative on TILDE`); use `expr ^ 0xFF` instead (but see §9).
- A leading constant such as `0xFF - (...) = ...` is rejected
  (`no viable alternative on HEX_INT`): the left side must start with a symbol.

## 8. Disassembly action (context tracking)

```sleigh
[ key = key - 0x64; ]
```

This is where SLEIGH **commits a context change** (the left-hand side is a
context variable). It is evaluated at disassembly time and affects how the next
instruction is decoded. `globalset` makes a change permanent for non-fallthrough
control flow (needed for branchy decoders).

## 9. Rolling-key opcode encryption (VMSpec-specific)

The dispatcher decrypts the raw opcode byte `byte` with the rolling key `key`:

```
cl = byte - key
cl = cl + 1
cl = ror8(cl, 4)
cl = cl - 0x85
cl = ~cl
key = key - cl          # rolling update
```

`cl` is the *decrypted* opcode (the value that selects the handler). A
constructor wants to match the *raw* byte given the key, so solve the decryption
for `byte`:

```
byte = rol8(~opcode + 0x85, 4) + key - 1
```

So each constructor's constraint is `byte = C + key - 1`, where the constant

```
C = rol8((0xFF ^ opcode + 0x85) & 0xFF, 4)
```

is computed per handler, and the disassembly action commits
`key = key - opcode`. This avoids `~`/`$or`/leading-constant problems entirely
and compiles cleanly.

```sleigh
:ld_data_u16 is byte = 0x2 + key - 1 [ key = key - 0x64; ] { }   # opcode 0x64 -> C=0x02
:ld_data_u32 is byte = 0x28 + key - 1 [ key = key - 0x2; ] { }   # opcode 0x02 -> C=0x28
```

## 10. Semantics (C-like, not raw P-Code)

The semantic section uses C-like syntax; raw P-Code opcodes (`LOAD`, `STORE`,
`CBRANCH`) are the *output* of the compiler, not valid input.

```sleigh
r1 = *:2 r2;          # LOAD 2 bytes from r2
*:2 r1 = r2;          # STORE 2 bytes to r1
tmp:4 = r2 + 4;       # named temporary (explicit size)
if (cond) goto addr;  # conditional branch — target is an OPERAND, not a label
goto addr;            # unconditional branch
call target;
```

There are no C-style `label:` + `goto label;` blocks: **branch targets are
operands** (family symbols that evaluate to an address). `local tmp = ...`
declares a named temporary.

## 11. What the paper leaves implicit (needs expansion)

- **Context syntax for the encryption register.** §5.1/§5.4 say "SLEIGH allows
  context modifications in disassembler expressions" but never show the
  `define context` / `key=(0,7)` / `[ key = ...; ]` spelling. This document
  fills that gap (§5, §8, §9).
- **Constant-propagation + dead-branch post-pass.** §5.4 mentions a
  post-disassembler pass (a Ghidra analyzer) but gives no implementation; our
  pipeline does not implement it yet.
- **Context flow across branches.** §5.4 notes SLEIGH "does not support updating
  the context based on control-flow decisions in P-Code" and defers to a plugin
  analyzer (`globalset`); we have not implemented that plugin.
- **Variable-length instructions.** The `;` concatenation operator (§7.4.4.1 of
  the SLEIGH manual) is required once handlers consume operands beyond the
  opcode byte; the current spec only models the single opcode byte.

## 12. Variable-length operands + P-Code semantics (implemented)

The skeleton now consumes operand bytes and emits P-Code bodies.

**Operand tokens.** Use one token per operand width and concatenate with `;`
so the instruction length is exactly 1 + operand_size bytes. A single
oversized token (e.g. `instr(40)` with overlapping `op1/op2/op4` fields)
forces *every* instruction to its full 5-byte width -- the disassembler skips
the intermediate opcodes.

```sleigh
define token instr(8)
  byte=(0,7)
;
define token data8(8)
  op1=(0,7)
;
define token data16(16)
  op2=(0,15)
;
define token data32(32)
  op4=(0,31)
;

:push_u32 is byte = 0x13; op4 unimpl   # 5 bytes (1 + 4)
:push_u8  is byte = 0x4B; op1 unimpl   # 2 bytes (1 + 1)
```

The `;` operator concatenates the opcode pattern with the operand field, which
is "don't care" (consumed without a constraint).

**Field in the semantics.** A token field is a varnode in the semantics body;
its value is the operand bits: `*:4 VSP = op4;`.

**zext/sext need an explicit-sized temporary.** `sext(op1)` on a raw token
field fails with `Could not resolve at least 1 variable size`; assign the field
to a sized temporary first:

```sleigh
tmp1:1 = op1;
tmp:4 = sext(tmp1);
```

`zext(x)`/`sext(x)` resolve their target size from the assignment target
(`tmp:4 = sext(tmp1)` → 4 bytes), not from the source.

## 13. EFLAGS (`pushfd`) and control flow (implemented)

The arithmetic handlers terminate with `pushfd`: the x86 EFLAGS of the
operation land on the VM stack, so the semantics compute the flag word by
hand over temporaries — SLEIGH's own flag registers are never involved.

**Comparisons produce a 1-byte boolean.** Assigning one directly to a wider
temporary is rejected (`Size restriction error in table 'instruction'`);
route it through a 1-byte temporary and `zext` (same pattern as §12):

```sleigh
cfb:1 = (tmpt < tmpa);
cf:4  = zext(cfb);
```

**`if` only accepts `goto`.** `if (cond) cf = 0;` does not parse
(`missing KEY_GOTO, unexpected IDENTIFIER`), and there are no labels to
jump to inside a constructor body. A conditional flag value must be
selected branchless; e.g. the SHL carry (bit `32-sh` of the operand, 0
when `sh == 0`):

```sleigh
kn:4   = 0x20:4 - sh;          # 32 - sh, in 1..32
kcl:4  = kn & 0x1F:4;          # keeps the shift itself in range
kmsk:4 = 0x1:4 ^ (kn >> 5);    # 0 exactly when sh == 0
cf:4   = ((eax >> kcl) & 1) & kmsk;
```

**Parity.** Constructor bodies have no loops; PF (even parity of the low
byte) is an XOR fold — bit 0 of `r ^ (r>>1) ^ ... ^ (r>>7)` is the
odd-parity indicator, so `pf = (fold & 1) ^ 1`.

**Bitwise `~` is fine in the semantics** (unlike in constraint patterns,
§7): `a:4 = ~tmpa;`.

**Indirect jump.** `goto [tmp];` — the brackets mark the varnode as the
destination address. Compute the target in a temporary first; the VM's
`jmp` is `pc = pop(4) + peek(4)`:

```sleigh
tv:4 = *:4 VSP;
VSP  = VSP + 4;
tp:4 = *:4 VSP;
tt:4 = tv + tp;
goto [tt];
```

**Native return (VM exit).** The `ret_native` handler ends in a native
`ret` whose target is read from the VM stack (after ten 4-byte context
pops). Model it as a p-code RETURN with that dynamically-read target:

```sleigh
VSP     = VSP + 40;       # pop ecx/ecx/edi/ebp/eflags/ebx/eax/edx/ebx/esi
retpc:4 = *:4 VSP;
VSP     = VSP + 4;
return [retpc];
```

`return` terminates flow without disassembling at the target — correct for
a VM exit whose target is native code outside the bytecode image (in the
runtime trace it is `0x01AF5FC7`, inside the engine blob but well past the
bytecode region). `goto [retpc]` would instead try to decode native x86 as
VM bytecode.
