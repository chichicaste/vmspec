# Fall-through con rolling-key en contexto: crítica progresiva de VMSpec §5.4

> Memoria de un negative result empírico contra la técnica del paper VMSpec
> (arXiv:2610.29566). Los tres experimentos se encadenan: cada uno responde al
> anterior, y juntos delimitan *por qué* la técnica del paper no salva el
> fall-through del disassembler de Ghidra para una rolling key por-instrucción.

## 1. La tesis del paper

VMSpec modela la rolling key del opcode como **variable de contexto de SLEIGH**.
Cada constructor emite el patrón de la cifra inversa:

```
:op is byte = 0x{C:X} + key - 1 [ key = key - 0x{opcode:X}; globalset(inst_next, key); ] { ... }
```

El `globalset(inst_next, key)` hace persistir el cambio de contexto a la
siguiente dirección. §5.4 reconoce que SLEIGH *"does not support updating the
context based on control-flow decisions"* y propone un *"lightweight analyzer
that updates each possible successor address"*.

## 2. Negativo 1 — el contexto en la ecuación rompe el fall-through

**Setup:** el patrón `byte = C + key - 1` con `globalset(inst_next, key)`.

**Resultado:** el disassembler decodifica **solo la 1ª instrucción**
(`st_data_u32_5` = opcode 0x14). Con patrón **constante** (`byte = 0x7B`) el
fall-through **sí** encadena (40+ instrucciones). La diferencia es únicamente
la variable `key` dentro del constraint.

**Hipótesis inicial:** el `globalset` es best-effort y la key no está disponible
cuando el sucesor se parsea (docs SLEIGH §8.3: *"a suggestion to the
disassembly engine"*).

## 3. Negativo 2 — el analyzer (fijar la key) no lo arregla

**Setup (respuesta a la hipótesis de §2):** pre-computar la key por dirección
con un sweep y fijarla vía `ProgramContext.setValue(keyReg, addr, addr, key)`,
luego `clearCodeUnits` + re-disassemble.

**Resultado:** la key queda **bien fijada** (`key@0x6575=0x75`, `0x6576=0x61`,
`0x6577=0x59`, `0x6578=0x59`), pero el disassembler **sigue decodificando 1
instrucción**.

**Conclusión parcial:** el fallo **no es de disponibilidad del contexto**, sino
del *flow analysis*: el constraint aritmético con contexto marca la instrucción
como "no fall-through".

## 4. Negativo 3 — el field-gating (contexto como campo) también falla

**Setup (respuesta a §3):** convertir el matching a constantes puras gateadas
por un *field* de contexto (el mecanismo `mode=1`/`TMode`, que sí soporta
fall-through):

```
:op_k75_b7B is key = 0x75 & byte = 0x7B { ... }
:op_k61_b27 is key = 0x61 & byte = 0x27 { ... }
```

Con la key fijada por dirección (`<context_data>` en el `.pspec`).

**Resultado:** **también 1 instrucción** (`op_k75_b7B` solo). Confirmado con un
spec mínimo de 2 constructores.

**Conclusión:** el `context-as-field` soporta fall-through solo cuando selecciona
**longitud/tamaño de operando** (TMode), **no** cuando selecciona el **valor del
opcode** (la identidad de la instrucción). Una variable de contexto en el
constraint del *byte del opcode* rompe el fall-through independientemente de
field vs ecuación.

## 5. Control positivo — decrypt a claro

**Setup:** desencriptar el bytecode (opcode → claro) con el sweep flow-sensitivo
`(addr, key)` y emitir el spec contra la codificación en claro (`byte = opcode`,
constante, sin contexto).

**Resultado:** **encadena** (15 instrucciones lineales hasta el primer `jmp`;
el sweep detiene correctamente en el control de flujo).

## 6. Implicación

La técnica de §5.4 (el analyzer) **no salva el fall-through** en SLEIGH para una
rolling key por-instrucción. La vía que funciona es el **decrypt a claro +
patrones constantes**, que es un recursive-sweep estilo §5.1 materializado como
imagen clara — no una concesión, sino la única vía compatible con el flow-engine
de Ghidra.

Este negative result (contexto-en-ecuación, analyzer, field-gating) **no lo
documentan** ni VMSpec §5.4 ni PUSHAN (arXiv:2603.18355); ambos esquivan el
fall-through haciendo su propio sweep/CFG en vez de delegar en Ghidra.

## Artefactos

| Aproach | Archivo | Resultado |
|---|---|---|
| Ecuación + globalset | `vmspec/sleigh_gen.py` (`_emit_ctor`) | 1 instr |
| Analyzer (setValue) | `ghidra/ApplyContext.java` | 1 instr |
| Field-gating | `tools/fieldgate_spec.py` | 1 instr |
| Decrypt a claro | `tools/decrypt_bytecode.py` + `vmspec/sweep.py` | ✅ encadena |
