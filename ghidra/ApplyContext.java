// Apply the pre-computed rolling-key context and re-disassemble.
//
// EXPERIMENT (documented result): the SLEIGH spec models the rolling key as a
// context variable (pattern ``byte = C + key - 1``). This script pins the key
// at each opcode address (pre-computed by tools/analyze_context.py) and then
// re-disassembles. The key IS set correctly (verified key@0x6576 = 0x61), yet
// the disassembler still decodes only the FIRST instruction: an arithmetic
// constraint with a context variable breaks the disassembler fall-through at
// the flow-analysis level (not a context-availability problem). The paper
// (§5.1) works around this with its own recursive sweep; the working approach
// in this repo is tools/decrypt_bytecode.py (decrypt to clear + constant
// patterns). Kept as a documented negative result.
//
// Usage (analyzeHeadless post-script, run from the repo root):
//   analyzeHeadless <proj> <name> -import <blob> -processor vmspec:LE:32:default
//       -scriptPath ghidra -postScript ApplyContext.java
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.ConsoleTaskMonitor;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ApplyContext extends GhidraScript {

    private static final long BC_ENTRY = 0x6575L;
    private static final long BC_END = 0x6703L;  // end of the swept range
    private static final int MAX_PRINT = 40;

    @Override
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var ctx = program.getProgramContext();
        var keyReg = program.getLanguage().getRegister("key");

        // read the (offset, key) pairs from data/context.txt (repo-root relative)
        var path = Paths.get("data", "context.txt");
        int count = 0;
        for (var line : Files.readAllLines(path)) {
            var parts = line.trim().split("\\s+");
            if (parts.length != 2) {
                continue;
            }
            long off = Long.parseLong(parts[0], 16);
            int key = Integer.parseInt(parts[1], 16);
            var addr = space.getAddress(off);
            ctx.setValue(keyReg, addr, addr, BigInteger.valueOf(key));
            count++;
        }
        println("set key context at " + count + " addresses");

        // diagnostic: read back the key at a few addresses
        for (long off : new long[] {0x6575L, 0x6576L, 0x6577L, 0x6578L}) {
            var a = space.getAddress(off);
            var v = ctx.getValue(keyReg, a, false);
            println(String.format("key@0x%X = %s", off, v));
        }

        // re-disassemble over the swept range
        var entry = space.getAddress(BC_ENTRY);
        var end = space.getAddress(BC_END);
        listing.clearCodeUnits(entry, end, false);
        var dis = Disassembler.getDisassembler(program, new ConsoleTaskMonitor(), null);
        dis.disassemble(entry, null);

        var ins = listing.getInstructionAt(entry);
        int n = 0;
        while (ins != null && n < MAX_PRINT) {
            println(String.format("%08x  %s", ins.getAddress().getOffset(), ins.toString()));
            ins = ins.getNext();
            n++;
        }
        println("total: " + n);
    }
}
