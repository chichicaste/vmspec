// Dump the VMSpec bytecode disassembly.
//
// Usage (analyzeHeadless post-script):
//   analyzeHeadless <proj> <name> -import <blob> -processor vmspec:LE:32:default
//       -scriptPath ghidra -postScript DumpDisasm.java
//
// Disassembles from the bytecode entry (0x6575 in the raw blob loaded at 0)
// and prints the first instructions. Used to verify the phase-6 disassembly
// (that the rolling key / clear opcodes decode and the fall-through chains).
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.ConsoleTaskMonitor;

public class DumpDisasm extends GhidraScript {

    private static final long BYTECODE_ENTRY = 0x6575L;
    private static final int MAX_INSTRUCTIONS = 40;

    @Override
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var entry = space.getAddress(BYTECODE_ENTRY);
        var dis = Disassembler.getDisassembler(program, new ConsoleTaskMonitor(), null);

        dis.disassemble(entry, null);

        var ins = listing.getInstructionAt(entry);
        int count = 0;
        while (ins != null && count < MAX_INSTRUCTIONS) {
            println(String.format("%08x  %s", ins.getAddress().getOffset(), ins.toString()));
            ins = ins.getNext();
            count++;
        }
        println("total: " + count);
    }
}
