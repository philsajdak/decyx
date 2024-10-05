# Python extension that leverages Anthropic's Claude to assist in reverse engineering and binary analysis.
# @author Phil Sajdak
# @category AI Analysis
# @keybinding Shift R
# @menupath
# @toolbar

from ghidra.framework.preferences import Preferences
from decyx.config import CLAUDE_MODELS, SKIP_PROMPT_CONFIRMATION
from decyx.api import get_response_from_claude
from decyx.decompiler import decompile_function, decompile_callers
from decyx.utils import (
    apply_selected_suggestions, apply_line_comments, apply_explanation,
    prepare_prompt
)
from decyx.gui import *

def get_api_key(preferences):
    """
    Retrieve the API key from Ghidra's preferences. If the key does not exist,
    prompt the user to input the Anthropic Claude API key and store it in the preferences.
    """
    api_key = preferences.getProperty("ANTHROPIC_API_KEY")
    if not api_key:
        api_key = askString("API Key", "Enter your Anthropic Claude API key:", "")
        if api_key:
            preferences.setProperty("ANTHROPIC_API_KEY", api_key)
            preferences.store()
            print "Anthropic API Key stored in {}.".format(preferences.getFilename())
    return api_key

def get_callers_code(func, current_program, monitor):
    """
    Get the decompiled code of the functions that call the current function.
    This is useful for additional context in the analysis.
    """
    callers = func.getCallingFunctions(monitor)
    if not callers:
        return None
    
    print "Found {} caller(s) for the current function.".format(len(callers))
    selected_callers = show_caller_selection_dialog(list(callers), current_program, monitor)
    return decompile_callers(selected_callers, current_program, monitor) if selected_callers else None

def process_action(action, func, current_program, monitor, api_key, model, callers_code):
    """
    Process a specific action on the decompiled function, sending the data to the Claude API and applying the response.
    Actions can include renaming, retyping variables, adding explanations, and inserting line comments.
    """
    decompiled_code, variables = decompile_function(func, current_program, monitor, annotate_addresses=(action == 'line_comments'))
    if not decompiled_code or not variables:
        print "Failed to obtain decompiled code or variable information for {}.".format(action)
        return False

    prompt = prepare_prompt(decompiled_code, variables, action=action, callers_code=callers_code)
    final_prompt = prompt if SKIP_PROMPT_CONFIRMATION else show_prompt_review_dialog(prompt, "Review and Edit Prompt ({})".format(action.replace('_', ' ').title()))
    if not final_prompt:
        print "Prompt review cancelled by user."
        return False

    is_explanation = action == 'explanation'
    response = get_response_from_claude(final_prompt, api_key, model, monitor, is_explanation=is_explanation)
    if not response:
        print "Failed to get {} from Claude API.".format(action.replace('_', ' '))
        return False

    if action == 'rename_retype':
        selected_suggestions = show_suggestion_dialog(response, variables, state.getTool())
        if selected_suggestions:
            apply_selected_suggestions(func, response, selected_suggestions, state.getTool())
        else:
            print "Operation cancelled by user after receiving suggestions."
            return False
    elif action == 'explanation':
        apply_explanation(func, response)
    elif action == 'line_comments':
        apply_line_comments(func, response)

    return True

def main():
    """
    The main entry point of the script. Responsible for gathering API keys, 
    selecting models and actions, and processing the actions on the current function.
    """
    api_key = get_api_key(Preferences)
    if not api_key:
        print "API key is required to proceed."
        return

    if len(CLAUDE_MODELS) == 1:
        model = CLAUDE_MODELS[0]
        print "Using the only available model: {}".format(model)
    else:
        model = show_model_select_dialog(CLAUDE_MODELS)
        if not model:
            print "Model selection cancelled by user."
            return

    selected_actions = show_action_select_dialog()
    if not selected_actions:
        print "No actions selected. Exiting."
        return

    func = getFunctionContaining(currentAddress)
    if not func or not currentProgram or not monitor:
        print "Required context is missing."
        return

    callers_code = get_callers_code(func, currentProgram, monitor)
    print "Callers' code {}.".format("included for additional context" if callers_code else "not included")

    for action in selected_actions:
        print "Processing action: {}".format(action)
        if not process_action(action, func, currentProgram, monitor, api_key, model, callers_code):
            print "Failed to process action: {}".format(action)
            return

    print "Decyx operations completed successfully."

if __name__ == "__main__":
    main()