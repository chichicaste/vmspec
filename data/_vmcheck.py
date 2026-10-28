import struct
from vmspec.vm import VM, handler_effect, ENGINE, OPERAND_LEN, FRAME, SP0, DISP, KEY, SCR
from vmspec.operand import decrypt_operand, handler_key_update
from vmspec.sweep import decrypt

dbin = open('data/vm_dbin.bin', 'rb').read()
tbl = list(struct.unpack_from('<256I', dbin, 0x5000))
vm = VM(dbin)
for i, v in enumerate(FRAME):
    vm.wr(SP0 + i * 4, v.to_bytes(4, 'little'))

pc = 0x1AE7575
key = 0x407575
for step in range(100):
    byte = dbin[pc - ENGINE]
    op = decrypt(byte, key & 0xFF)
    key = (key & ~0xFF) | ((key & 0xFF) - op & 0xFF)
    hoff = tbl[op] - ENGINE
    olen = OPERAND_LEN.get(hoff, 0)
    operand = dbin[pc + 1 - ENGINE:pc + 1 + olen - ENGINE]
    clear = decrypt_operand(hoff, operand, key)
    key = handler_key_update(hoff, clear or b'', key)

    if hoff == 0x304:
        esp = vm.esp
        v = vm.pop(4)
        pk = vm.peek()
        print(f'jmp step={step} esp=0x{esp:08x}')
        print(f'  v(pop)=0x{v:08x}  pk(peek)=0x{pk:08x}  target=0x{(v + pk) & 0xffffffff:08x}')
        print(f'  (DISP+KEY=0x{(DISP + KEY) & 0xffffffff:08x} es la premisa del comentario del C++, no el target real)')
        for i in range(8):
            a = esp + i * 4
            val = int.from_bytes(vm.rd(a, 4), 'little')
            print(f'  stack[0x{a:08x}] = 0x{val:08x}')
        print('  data region (SCR):')
        for i in range(16):
            a = ENGINE + SCR + i * 4
            val = int.from_bytes(vm.rd(a, 4), 'little')
            print(f'    data[0x{i * 4:02X}] = 0x{val:08x}')
        break

    target = handler_effect(hoff, op, clear, vm)
    if target is None:
        print('ret_native step', step)
        break
    pc = pc + 1 + olen if target == -1 else target
