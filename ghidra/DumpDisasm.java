// Dump the VMSpec bytecode disassembly (all decrypted segments).
//
// Usage (analyzeHeadless post-script):
//   analyzeHeadless <proj> <name> -import <blob> -processor vmspec:LE:32:32:default
//       -scriptPath ghidra -postScript DumpDisasm.java
//
// Disassembles from each decrypted segment entry (segment 1 at 0x6575, segment
// 2 at 0x63DA -- the jmp target) and prints the instructions. Used to verify
// the phase-6 disassembly (that the clear opcodes decode and the fall-through
// chains across the whole program).
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.ConsoleTaskMonitor;

public class DumpDisasm extends GhidraScript {

    private static final long[] SEGMENT_ENTRIES = { 0x6575L, 0x63DAL };
    private static final int MAX_INSTRUCTIONS = 200;

    @Override
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var dis = Disassembler.getDisassembler(program, new ConsoleTaskMonitor(), null);

        for (long entry : SEGMENT_ENTRIES) {
            var addr = space.getAddress(entry);
            dis.disassemble(addr, null);
            var ins = listing.getInstructionAt(addr);
            int count = 0;
            while (ins != null && count < MAX_INSTRUCTIONS) {
                println(String.format("%08x  %s", ins.getAddress().getOffset(), ins.toString()));
                ins = ins.getNext();
                count++;
            }
            println("segment@0x" + Long.toHexString(entry) + " total: " + count);
        }
    }
}
