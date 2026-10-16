//@category REA Verification

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

/** Rename one source-owned fixture entry in the caller's saved project. */
public final class ReaExistingCopyRename extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected entry address and function name");
        }
        Function function = getFunctionAt(toAddr(args[0]));
        if (function == null) {
            throw new IllegalStateException("Fixture function was not recovered");
        }
        function.setName(args[1], SourceType.USER_DEFINED);
        println("REA_EXISTING_COPY_RENAMED " + args[1]);
    }
}
