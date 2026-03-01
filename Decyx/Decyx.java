// Java extension that leverages Anthropic's Claude to assist in reverse engineering and binary analysis.
// @author Phil Sajdak
// @category AI Analysis
// @keybinding Shift R
// @menupath
// @toolbar

import com.google.gson.JsonObject;
import decyx.ClaudeApi;
import decyx.DecyxConfig;
import decyx.DecompilerHelper;
import decyx.DecompilerHelper.DecompileResult;
import decyx.SuggestionUtils;
import decyx.dialogs.ActionSelectionDialog;
import decyx.dialogs.CallerSelectionDialog;
import decyx.dialogs.ModelSelectionDialog;
import decyx.dialogs.PromptReviewDialog;
import decyx.dialogs.SuggestionDialog;
import ghidra.app.script.GhidraScript;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Decyx extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // Get API key
        String apiKey = getApiKey();
        if (apiKey == null || apiKey.isEmpty()) {
            println("API key is required to proceed.");
            return;
        }

        // Select model
        String model;
        List<String> models = DecyxConfig.CLAUDE_MODELS;
        if (models.size() == 1) {
            model = models.get(0);
            println("Using the only available model: " + model);
        } else {
            model = ModelSelectionDialog.showDialog(models);
            if (model == null) {
                println("Model selection cancelled by user.");
                return;
            }
        }

        // Select actions
        List<String> selectedActions = ActionSelectionDialog.showDialog();
        if (selectedActions.isEmpty()) {
            println("No actions selected. Exiting.");
            return;
        }

        // Get current function context
        Function func = getFunctionContaining(currentAddress);
        if (func == null || currentProgram == null || monitor == null) {
            println("Required context is missing.");
            return;
        }

        // Get callers' code for additional context
        Map<String, String> callersCode = getCallersCode(func);
        println("Callers' code " + (callersCode != null ? "included for additional context" : "not included") + ".");

        // Process each selected action
        for (String action : selectedActions) {
            println("Processing action: " + action);
            if (!processAction(action, func, apiKey, model, callersCode)) {
                println("Failed to process action: " + action);
                return;
            }
        }

        println("Decyx operations completed successfully.");
    }

    /**
     * Retrieves the API key from Ghidra's preferences, prompting the user if not stored.
     */
    private String getApiKey() throws Exception {
        String apiKey = Preferences.getProperty("ANTHROPIC_API_KEY");
        if (apiKey == null || apiKey.isEmpty()) {
            apiKey = askString("API Key", "Enter your Anthropic Claude API key:", "");
            if (apiKey != null && !apiKey.isEmpty()) {
                Preferences.setProperty("ANTHROPIC_API_KEY", apiKey);
                Preferences.store();
                println("Anthropic API Key stored in " + Preferences.getFilename() + ".");
            }
        }
        return apiKey;
    }

    /**
     * Gets the decompiled code of functions that call the current function.
     */
    private Map<String, String> getCallersCode(Function func) {
        Set<Function> callers = func.getCallingFunctions(monitor);
        if (callers == null || callers.isEmpty()) {
            return null;
        }

        println("Found " + callers.size() + " caller(s) for the current function.");
        List<Function> callerList = new ArrayList<>(callers);
        List<Function> selectedCallers = CallerSelectionDialog.showDialog(callerList, currentProgram, monitor);

        if (selectedCallers == null || selectedCallers.isEmpty()) {
            return null;
        }

        return DecompilerHelper.decompileCallers(selectedCallers, currentProgram, monitor);
    }

    /**
     * Processes a specific action on the decompiled function.
     */
    private boolean processAction(String action, Function func, String apiKey, String model,
                                   Map<String, String> callersCode) {
        boolean annotateAddresses = "line_comments".equals(action);
        DecompileResult decompResult = DecompilerHelper.decompileFunction(func, currentProgram, monitor, annotateAddresses);
        if (decompResult == null || decompResult.code == null || decompResult.variables == null) {
            println("Failed to obtain decompiled code or variable information for " + action + ".");
            return false;
        }

        String prompt = SuggestionUtils.preparePrompt(decompResult.code, decompResult.variables, action, callersCode);
        String finalPrompt;
        if (DecyxConfig.SKIP_PROMPT_CONFIRMATION) {
            finalPrompt = prompt;
        } else {
            String title = "Review and Edit Prompt (" + action.replace("_", " ").substring(0, 1).toUpperCase() +
                action.replace("_", " ").substring(1) + ")";
            finalPrompt = PromptReviewDialog.showDialog(prompt, title);
        }

        if (finalPrompt == null) {
            println("Prompt review cancelled by user.");
            return false;
        }

        boolean isExplanation = "explanation".equals(action);
        Object response = ClaudeApi.getResponseFromClaude(finalPrompt, apiKey, model, monitor, isExplanation);
        if (response == null) {
            println("Failed to get " + action.replace("_", " ") + " from Claude API.");
            return false;
        }

        switch (action) {
            case "rename_retype":
                JsonObject suggestions = (JsonObject) response;
                JsonObject selectedSuggestions = SuggestionDialog.showDialog(suggestions, decompResult.variables, state.getTool());
                if (selectedSuggestions != null) {
                    SuggestionUtils.applySelectedSuggestions(func, suggestions, selectedSuggestions, state.getTool());
                } else {
                    println("Operation cancelled by user after receiving suggestions.");
                    return false;
                }
                break;

            case "explanation":
                SuggestionUtils.applyExplanation(func, (String) response);
                break;

            case "line_comments":
                SuggestionUtils.applyLineComments(func, (JsonObject) response);
                break;
        }

        return true;
    }
}
