package decyx;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for interfacing with Ghidra's decompiler.
 */
public class DecompilerHelper {

    /**
     * Result of decompiling a function: the decompiled code and extracted variables.
     */
    public static class DecompileResult {
        public final String code;
        public final List<Map<String, String>> variables;

        public DecompileResult(String code, List<Map<String, String>> variables) {
            this.code = code;
            this.variables = variables;
        }
    }

    /**
     * Initializes and configures the Ghidra Decompiler interface.
     */
    public static DecompInterface initializeDecompiler() {
        DecompInterface decompInterface = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompInterface.setOptions(options);
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        return decompInterface;
    }

    /**
     * Recursively traverses a Clang AST node, applying a callback to each node.
     */
    public static void traverseClangNode(ClangNode node, ClangNodeCallback callback) {
        callback.visit(node);
        for (int i = 0; i < node.numChildren(); i++) {
            ClangNode child = node.Child(i);
            traverseClangNode(child, callback);
        }
    }

    /**
     * Callback interface for traversing Clang AST nodes.
     */
    public interface ClangNodeCallback {
        void visit(ClangNode node);
    }

    /**
     * Annotates the decompiled code with addresses from the Clang AST.
     */
    public static String annotateCodeWithAddresses(ClangNode codeMarkup) {
        List<String> annotatedLines = new ArrayList<>();

        traverseClangNode(codeMarkup, node -> {
            if (node instanceof ClangStatement) {
                ClangStatement stmt = (ClangStatement) node;
                Address address = stmt.getMinAddress();
                String codeLine = stmt.toString();
                if (address != null) {
                    annotatedLines.add("// Address: " + address + "\n" + codeLine);
                } else {
                    annotatedLines.add(codeLine);
                }
            }
        });

        return String.join("\n", annotatedLines);
    }

    /**
     * Identifies global variables in the decompiled code based on naming patterns.
     */
    public static Set<String> findGlobalVariables(String decompiledCode) {
        Set<String> globalVariables = new LinkedHashSet<>();
        for (Pattern pattern : DecyxConfig.GLOBAL_VARIABLE_PATTERNS) {
            Matcher matcher = pattern.matcher(decompiledCode);
            while (matcher.find()) {
                globalVariables.add(matcher.group());
            }
        }
        return globalVariables;
    }

    /**
     * Extracts information about global variables from the program's symbol table.
     */
    public static List<Map<String, String>> extractGlobalVariables(Set<String> globalVars, Program currentProgram) {
        List<Map<String, String>> globalVarInfo = new ArrayList<>();
        var symbolTable = currentProgram.getSymbolTable();

        for (String globalVar : globalVars) {
            List<Symbol> symbols = symbolTable.getGlobalSymbols(globalVar);
            String dataType = "unknown";

            if (symbols != null && !symbols.isEmpty()) {
                Symbol symbol = symbols.get(0);
                if (symbol.getSymbolType() == SymbolType.LABEL) {
                    Address addr = symbol.getAddress();
                    Data data = currentProgram.getListing().getDataAt(addr);
                    if (data != null) {
                        dataType = data.getDataType().toString();
                    }
                } else {
                    Object obj = symbol.getObject();
                    if (obj instanceof Data) {
                        dataType = ((Data) obj).getDataType().toString();
                    }
                }
            }

            Map<String, String> info = new HashMap<>();
            info.put("old_name", globalVar);
            info.put("old_type", dataType);
            info.put("storage", "global");
            globalVarInfo.add(info);
        }

        return globalVarInfo;
    }

    /**
     * Extracts all relevant variables from the function, including parameters, locals, and globals.
     */
    public static List<Map<String, String>> extractVariables(Function func, String decompiledCode, Program currentProgram) {
        List<Map<String, String>> allVars = new ArrayList<>();

        // Extract parameters
        for (Parameter param : func.getParameters()) {
            Map<String, String> varInfo = new HashMap<>();
            varInfo.put("old_name", param.getName());
            varInfo.put("old_type", param.getDataType().toString());
            varInfo.put("storage", param.getVariableStorage().toString());
            allVars.add(varInfo);
        }

        // Extract local variables
        for (Variable localVar : func.getLocalVariables()) {
            Map<String, String> varInfo = new HashMap<>();
            varInfo.put("old_name", localVar.getName());
            varInfo.put("old_type", localVar.getDataType().toString());
            varInfo.put("storage", localVar.getVariableStorage().toString());
            allVars.add(varInfo);
        }

        // Identify and extract global variables
        Set<String> globalVars = findGlobalVariables(decompiledCode);
        allVars.addAll(extractGlobalVariables(globalVars, currentProgram));

        // Filter out variables with 'HASH' in their storage
        allVars.removeIf(var -> var.get("storage").contains("HASH"));

        return allVars;
    }

    /**
     * Decompiles a given function to retrieve its C code and variable information.
     *
     * @param func              the function to decompile
     * @param currentProgram    the current program context in Ghidra
     * @param monitor           the monitor object for progress tracking
     * @param annotateAddresses whether to annotate the decompiled code with addresses
     * @return a DecompileResult, or null if decompilation fails
     */
    public static DecompileResult decompileFunction(Function func, Program currentProgram,
                                                     TaskMonitor monitor, boolean annotateAddresses) {
        DecompInterface decompInterface = initializeDecompiler();
        decompInterface.openProgram(currentProgram);

        try {
            DecompileResults results = decompInterface.decompileFunction(func, 60, monitor);
            if (!results.decompileCompleted()) {
                System.out.println("Decompilation failed for function at " + func.getEntryPoint());
                return null;
            }

            System.out.println("Decompilation completed successfully.");
            HighFunction highFunc = results.getHighFunction();
            ClangNode codeMarkup = results.getCCodeMarkup();

            // Commit local names to database within a transaction
            if (highFunc != null) {
                int transaction = currentProgram.startTransaction("Commit Local Names");
                try {
                    HighFunctionDBUtil.commitLocalNamesToDatabase(highFunc, SourceType.USER_DEFINED);
                } catch (Exception e) {
                    System.out.println("Warning: Could not commit local names to database: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(transaction, true);
                }
            }

            String decompiledCodeStr;
            if (annotateAddresses) {
                decompiledCodeStr = annotateCodeWithAddresses(codeMarkup);
            } else {
                decompiledCodeStr = results.getDecompiledFunction().getC();
            }

            List<Map<String, String>> variables = extractVariables(func, decompiledCodeStr, currentProgram);
            return new DecompileResult(decompiledCodeStr, variables);

        } catch (Exception e) {
            System.out.println("Exception during decompilation: " + e.getMessage());
            return null;
        } finally {
            decompInterface.dispose();
        }
    }

    /**
     * Decompiles a list of caller functions to provide additional context.
     *
     * @param callers        a list of caller Function objects
     * @param currentProgram the current program context in Ghidra
     * @param monitor        the monitor object for progress tracking
     * @return a map of caller names to their decompiled code
     */
    public static Map<String, String> decompileCallers(List<Function> callers, Program currentProgram,
                                                        TaskMonitor monitor) {
        DecompInterface decompInterface = initializeDecompiler();
        decompInterface.openProgram(currentProgram);

        Map<String, String> callersCode = new LinkedHashMap<>();
        int totalCallers = callers.size();

        try {
            for (int index = 0; index < totalCallers; index++) {
                if (monitor.isCancelled()) {
                    System.out.println("Decompilation cancelled by user.");
                    break;
                }

                Function caller = callers.get(index);
                int progressPercentage = (int) (((index + 1) / (float) totalCallers) * 100);
                monitor.setProgress(progressPercentage);

                try {
                    DecompileResults results = decompInterface.decompileFunction(caller, 60, monitor);
                    if (results.decompileCompleted()) {
                        String decompiledCode = results.getDecompiledFunction().getC();
                        callersCode.put(caller.getName(), decompiledCode);
                        System.out.println("Decompiled caller '" + caller.getName() + "' successfully.");
                    } else {
                        callersCode.put(caller.getName(), "Decompilation failed.");
                        System.out.println("Decompilation failed for caller '" + caller.getName() + "'.");
                    }
                } catch (Exception e) {
                    callersCode.put(caller.getName(), "Exception during decompilation: " + e.getMessage());
                    System.out.println("Exception during decompilation of caller '" + caller.getName() + "': " + e.getMessage());
                }
            }
        } finally {
            decompInterface.dispose();
        }

        return callersCode;
    }
}
