// Decompile the VMSpec bytecode segments with Ghidra's decompiler.
//
// Usage (analyzeHeadless post-script):
//   analyzeHeadless <proj> <name> -import <blob> -processor vmspec:LE:32:default
//       -scriptPath ghidra -postScript DumpDecomp.java
//
// Disassembles each decrypted segment (0x6575, 0x63DA), creates a function over
// its fall-through body, and prints the decompiled C. Verifies the phase-6
// P-Code semantics produce decompilable output (the stack machine lifted back
// into C-like form).
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;

public class DumpDecomp extends GhidraScript {

    private static final long[] SEGMENT_ENTRIES = { 0x6575L, 0x63DAL };
    private static final int MAX_BODY = 512;

    @Override
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var dis = Disassembler.getDisassembler(program, new ConsoleTaskMonitor(), null);
        var fm = program.getFunctionManager();

        var ifc = new DecompInterface();
        ifc.openProgram(program);

        int seg = 1;
        for (long entry : SEGMENT_ENTRIES) {
            var addr = space.getAddress(entry);
            dis.disassemble(addr, null);

            // collect the fall-through body (stops at the jmp / ret, which have
            // no fall-through)
            var set = new AddressSet();
            var ins = listing.getInstructionAt(addr);
            while (ins != null && set.getNumAddresses() < MAX_BODY) {
                set.add(ins.getMinAddress(), ins.getMaxAddress());
                var next = ins.getFallThrough();
                if (next == null) {
                    break;
                }
                ins = listing.getInstructionAt(next);
            }

            var name = "seg" + seg;
            var func = fm.getFunctionAt(addr);
            if (func == null) {
                fm.createFunction(name, addr, set, SourceType.USER_DEFINED);
                func = fm.getFunctionAt(addr);
            }

            // pin the VPC (program counter) register to the entry address so
            // the decompiler knows where it starts
            var ctx = program.getProgramContext();
            var vpc = program.getLanguage().getRegister("VPC");
            if (vpc != null) {
                ctx.setValue(vpc, addr, addr, java.math.BigInteger.valueOf(entry));
            }

            println("=== " + name + " @ 0x" + Long.toHexString(entry)
                    + " (body " + set.getNumAddresses() + " bytes) ===");
            DecompileResults res = ifc.decompileFunction(func, 60, monitor);
            var df = res.getDecompiledFunction();
            if (df != null) {
                println(df.getC());
            } else {
                println("decompile failed: " + res.getErrorMessage());
            }
            seg++;
        }
    }
}
