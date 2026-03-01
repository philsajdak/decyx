package decyx;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Utility methods for applying AI-generated suggestions to the Ghidra program.
 */
public class SuggestionUtils {

    /**
     * Finds a data type by its name from the data type manager.
     */
    public static DataType findDataTypeByName(String name, PluginTool tool) {
        DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
        if (service == null) {
            return null;
        }

        DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
        for (DataTypeManager manager : dataTypeManagers) {
            // Try with and without leading slash
            DataType dataType = manager.getDataType("/" + name);
            if (dataType == null) {
                dataType = manager.getDataType(name);
            }
            if (dataType != null) {
                return dataType;
            }

            // If not found, search through all data types
            Iterator<DataType> allDataTypes = manager.getAllDataTypes();
            while (allDataTypes.hasNext()) {
                DataType dt = allDataTypes.next();
                if (dt.getName().equalsIgnoreCase(name)) {
                    return dt;
                }
            }
        }

        return null;
    }

    /**
     * Changes the data type of a variable.
     */
    public static boolean retypeVariable(Variable variable, String newTypeName, PluginTool tool) {
        DataType newDataType = findDataTypeByName(newTypeName, tool);
        if (newDataType == null) {
            return false;
        }

        try {
            variable.setDataType(newDataType, SourceType.USER_DEFINED);
            System.out.println("Successfully retyped variable '" + variable.getName() + "' to '" + newTypeName + "'");
            return true;
        } catch (VariableSizeException e) {
            System.out.println("Error: Variable size conflict when retyping '" + variable.getName() +
                "' to '" + newTypeName + "'. Details: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("Error retyping variable '" + variable.getName() + "' to '" + newTypeName + "': " + e.getMessage());
            return false;
        }
    }

    /**
     * Retypes a global variable.
     */
    public static void retypeGlobalVariable(Listing listing, Symbol symbol, DataType newDataType) {
        Address addr = symbol.getAddress();
        try {
            listing.clearCodeUnits(addr, addr.add(newDataType.getLength() - 1), false);
            Data data = listing.createData(addr, newDataType);
            if (data != null) {
                System.out.println("Retyped global variable '" + symbol.getName() + "' to '" + newDataType.getName() + "'");
            } else {
                Data existingData = listing.getDataAt(addr);
                if (existingData != null) {
                    existingData.setDataType(newDataType);
                    System.out.println("Modified existing data type for global variable '" + symbol.getName() +
                        "' to '" + newDataType.getName() + "'");
                } else {
                    System.out.println("Error: Failed to create or modify data for global variable '" +
                        symbol.getName() + "' with type '" + newDataType.getName() + "'");
                }
            }
        } catch (Exception e) {
            System.out.println("Error retyping global variable '" + symbol.getName() + "' to '" +
                newDataType.getName() + "': " + e.getMessage());
        }
    }

    /**
     * Renames the given function.
     */
    public static void renameFunction(Function func, String newName) throws Exception {
        func.setName(newName, SourceType.USER_DEFINED);
        System.out.println("Renamed function to '" + newName + "'");
    }

    /**
     * Renames the given symbol.
     */
    public static void renameSymbol(Symbol symbol, String newName) throws Exception {
        String oldName = symbol.getName();
        symbol.setName(newName, SourceType.USER_DEFINED);
        System.out.println("Renamed variable '" + oldName + "' to '" + newName + "'");
    }

    /**
     * Processes a global variable for renaming and retyping.
     */
    public static void processGlobalVariable(SymbolTable symbolTable, Listing listing,
                                              String oldName, String newName, String newTypeName, PluginTool tool) {
        String lookupName = oldName.startsWith("_") ? oldName.substring(1) : oldName;

        SymbolIterator symbols = symbolTable.getSymbols(lookupName);
        Symbol symbol = symbols.hasNext() ? symbols.next() : null;

        if (symbol != null) {
            try {
                if (newName != null && !newName.isEmpty()) {
                    renameSymbol(symbol, newName);
                }
                if (newTypeName != null && !newTypeName.isEmpty()) {
                    DataType newDataType = findDataTypeByName(newTypeName, tool);
                    if (newDataType != null) {
                        retypeGlobalVariable(listing, symbol, newDataType);
                    } else {
                        System.out.println("Data type '" + newTypeName + "' not found for global variable '" + symbol.getName() + "'");
                    }
                }
            } catch (Exception e) {
                System.out.println("Error processing global variable '" + oldName + "': " + e.getMessage());
            }
        } else {
            System.out.println("Global variable '" + lookupName + "' not found");
        }
    }

    /**
     * Processes a local variable for renaming and retyping.
     */
    public static void processLocalVariable(Variable varObj, String newName, String newTypeName, PluginTool tool) {
        try {
            if (newName != null && !newName.isEmpty()) {
                renameSymbol(varObj.getSymbol(), newName);
            }
            if (newTypeName != null && !newTypeName.isEmpty()) {
                boolean success = retypeVariable(varObj, newTypeName, tool);
                if (!success) {
                    System.out.println("Warning: Failed to retype variable '" + varObj.getName() +
                        "' to '" + newTypeName + "'. Skipping and continuing with other variables.");
                }
            }
        } catch (Exception e) {
            System.out.println("Error processing local variable: " + e.getMessage());
        }
    }

    /**
     * Applies the selected suggestions for renaming and retyping of variables and functions.
     *
     * @param func        the function being modified
     * @param suggestions the original suggestions from Claude API
     * @param selected    the selected suggestions to apply
     * @param tool        the tool context for data type operations
     */
    public static void applySelectedSuggestions(Function func, JsonObject suggestions,
                                                 JsonObject selected, PluginTool tool) {
        Program program = func.getProgram();
        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();

        // Apply function name if selected
        String functionName = selected.has("function_name") && !selected.get("function_name").isJsonNull()
            ? selected.get("function_name").getAsString() : null;
        if (functionName != null && !functionName.isEmpty()) {
            try {
                renameFunction(func, functionName);
            } catch (Exception e) {
                System.out.println("Error renaming function: " + e.getMessage());
            }
        }

        // Gather all parameters and local variables
        Parameter[] params = func.getParameters();
        Variable[] locals = func.getLocalVariables();
        Variable[] allVars = new Variable[params.length + locals.length];
        System.arraycopy(params, 0, allVars, 0, params.length);
        System.arraycopy(locals, 0, allVars, params.length, locals.length);

        // Process variable suggestions
        JsonArray suggestedVars = suggestions.getAsJsonArray("variables");
        JsonArray selectedVars = selected.getAsJsonArray("variables");

        for (int i = 0; i < selectedVars.size(); i++) {
            JsonElement elem = selectedVars.get(i);
            if (elem.isJsonNull()) {
                continue;
            }
            JsonObject varSuggestion = elem.getAsJsonObject();

            String oldName = suggestedVars.get(i).getAsJsonObject().get("old_name").getAsString();
            String newName = varSuggestion.has("new_name") ? varSuggestion.get("new_name").getAsString() : null;
            String newType = varSuggestion.has("new_type") ? varSuggestion.get("new_type").getAsString() : null;

            if (oldName.contains("DAT")) {
                processGlobalVariable(symbolTable, listing, oldName, newName, newType, tool);
            } else {
                Variable varObj = findVariableByName(allVars, oldName);
                if (varObj != null) {
                    processLocalVariable(varObj, newName, newType, tool);
                } else {
                    System.out.println("Variable '" + oldName + "' not found in function");
                }
            }
        }
    }

    private static Variable findVariableByName(Variable[] vars, String name) {
        for (Variable v : vars) {
            if (v.getName().equals(name)) {
                return v;
            }
        }
        return null;
    }

    /**
     * Applies line comments to the assembly and decompiler views.
     */
    public static void applyLineComments(Function func, JsonObject comments) {
        Program program = func.getProgram();
        Listing listing = program.getListing();

        for (String addressStr : comments.keySet()) {
            String comment = comments.get(addressStr).getAsString();
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                System.out.println("Warning: Invalid address " + addressStr);
                continue;
            }

            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit != null) {
                codeUnit.setComment(CodeUnit.PRE_COMMENT, comment);
                System.out.println("Added PRE comment at address " + addressStr + ": " + comment);
            } else {
                System.out.println("Warning: No code unit found at address " + addressStr);
            }
        }

        System.out.println("Line comments have been applied to both assembly listing and decompiled function.");
    }

    /**
     * Applies an explanation as a comment to the function.
     */
    public static void applyExplanation(Function func, String explanation) {
        func.setComment(explanation);
        System.out.println("Added explanation as comment to the function.");
    }

    /**
     * Prepares a prompt with the given code and variables for AI interaction.
     */
    public static String preparePrompt(String code, List<Map<String, String>> variables,
                                        String action, Map<String, String> callersCode) {
        String promptTemplate = DecyxConfig.PROMPTS.get(action);
        if (promptTemplate == null) {
            return null;
        }

        StringBuilder prompt = new StringBuilder(promptTemplate);

        if (callersCode != null && !callersCode.isEmpty()) {
            prompt.append("### Additional Context: Callers' Code\n");
            for (Map.Entry<String, String> entry : callersCode.entrySet()) {
                prompt.append("#### Caller: ").append(entry.getKey())
                    .append("\n\n").append(entry.getValue()).append("\n\n\n");
            }
        }

        prompt.append("### Code:\n\n").append(code).append("\n\n");

        if (!"line_comments".equals(action)) {
            prompt.append("### Variables:\n\n").append(variablesToJson(variables)).append("\n\n");
        }

        return prompt.toString();
    }

    /**
     * Converts a list of variable maps to a JSON string.
     */
    private static String variablesToJson(List<Map<String, String>> variables) {
        JsonArray array = new JsonArray();
        for (Map<String, String> var : variables) {
            JsonObject obj = new JsonObject();
            for (Map.Entry<String, String> entry : var.entrySet()) {
                obj.addProperty(entry.getKey(), entry.getValue());
            }
            array.add(obj);
        }
        return array.toString();
    }

    /**
     * Fixes the formatting of pointer types by ensuring there is a space before each '*'.
     */
    public static String formatNewType(String typeStr) {
        if (typeStr == null || typeStr.isEmpty()) {
            return typeStr;
        }
        // Add space before '*' if not preceded by a space
        String fixed = typeStr.replaceAll("(?<!\\s)\\*", " *");
        // Handle multiple consecutive '*' characters
        StringBuilder sb = new StringBuilder();
        boolean lastWasStar = false;
        for (int i = 0; i < fixed.length(); i++) {
            char c = fixed.charAt(i);
            if (c == '*') {
                if (lastWasStar) {
                    sb.append(" *");
                } else {
                    sb.append(c);
                }
                lastWasStar = true;
            } else {
                lastWasStar = false;
                sb.append(c);
            }
        }
        // Clean up redundant spaces
        return sb.toString().replaceAll("\\s+", " ").trim();
    }
}
