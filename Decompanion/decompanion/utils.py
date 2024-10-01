# utils.py

import re
import json
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import VariableSizeException
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.listing import CodeUnit
from ghidra.app.script import GhidraScript
from config import PROMPTS

def find_data_type_by_name(name, tool):
    """
    Finds a data type by its name from the data type manager.

    Args:
        name (str): The name of the data type to search for.
        tool (Tool): The tool context to retrieve the data type manager.

    Returns:
        DataType: The matching data type if found, else None.
    """
    service = tool.getService(DataTypeManagerService)
    data_type_managers = service.getDataTypeManagers()
    
    for manager in data_type_managers:
        # Try with and without leading slash
        data_type = manager.getDataType("/" + name)
        if data_type is None:
            data_type = manager.getDataType(name)
        
        if data_type is not None:
            return data_type
        
        # If not found, search through all categories
        all_data_types = manager.getAllDataTypes()
        for dt in all_data_types:
            if dt.getName().lower() == name.lower():
                return dt
    
    return None

def retype_variable(variable, new_type_name, tool):
    """
    Changes the data type of a variable to a new specified type.

    Args:
        variable (Variable): The variable to be retyped.
        new_type_name (str): The name of the new data type.
        tool (Tool): The tool context to find the new data type.

    Returns:
        bool: True if successful, False otherwise.
    """
    new_data_type = find_data_type_by_name(new_type_name, tool)
    
    if new_data_type is None:
        return False
    
    try:
        variable.setDataType(new_data_type, SourceType.USER_DEFINED)
        print "Successfully retyped variable '{}' to '{}'".format(variable.getName(), new_type_name)
        return True
    except VariableSizeException as e:
        print "Error: Variable size conflict when retyping '{}' to '{}'. Details: {}".format(
            variable.getName(), new_type_name, str(e))
        return False
    except Exception as e:
        print "Error retyping variable '{}' to '{}': {}".format(
            variable.getName(), new_type_name, str(e))
        return False

def apply_selected_suggestions(func, suggestions, selected, tool):
    """
    Applies the selected suggestions for renaming and retyping of variables and functions.

    Args:
        func (Function): The function object being modified.
        suggestions (dict): The original suggestions for renaming/retyping.
        selected (dict): The selected suggestions to apply.
        tool (Tool): The tool context for data type operations.

    Returns:
        None
    """
    # Apply function name renaming
    if selected['function_name']:
        func.setName(selected['function_name'], SourceType.USER_DEFINED)
        print "Renamed function to '{}'".format(selected['function_name'])

    # Apply variable renaming and retyping
    all_vars = list(func.getParameters()) + list(func.getLocalVariables())
    symbol_table = func.getProgram().getSymbolTable()
    
    for i in range(len(suggestions['variables'])):
        var_suggestion = selected['variables'][i]
        if var_suggestion:
            old_name = suggestions['variables'][i]['old_name']
            new_name = var_suggestion.get('new_name', None)
            new_type_name = var_suggestion.get('new_type', None)
            
            # Check if it's a global variable (DAT_*)
            if old_name.startswith("DAT_"):
                symbols = symbol_table.getSymbols(old_name)
                symbol = next(symbols, None)  # Get the first symbol if it exists
                if symbol:
                    if new_name:
                        symbol.setName(new_name, SourceType.USER_DEFINED)
                        print "Renamed global variable '{}' to '{}'".format(old_name, new_name)
                    # Note: We can't change the type of global variables directly
                else:
                    print "Global variable '{}' not found".format(old_name)
            else:
                for var_obj in all_vars:
                    if var_obj.getName() == old_name:
                        if new_name:
                            var_obj.setName(new_name, SourceType.USER_DEFINED)
                            print "Renamed variable '{}' to '{}'".format(old_name, new_name)
                        if new_type_name:
                            success = retype_variable(var_obj, new_type_name, tool)
                            if not success:
                                print "Warning: Failed to retype variable '{}' to '{}'. Skipping and continuing with other variables.".format(var_obj.getName(), new_type_name)
                        break
                else:
                    print "Variable '{}' not found in function".format(old_name)

def apply_line_comments(func, comments):
    """
    Applies line comments to the assembly and decompiler views.

    Args:
        func (Function): The function to which comments are being applied.
        comments (dict): A dictionary of address-to-comment mappings.

    Returns:
        None
    """
    program = func.getProgram()
    listing = program.getListing()

    # Apply comments to both the assembly listing and the decompiler
    for address_str, comment in comments.items():
        address = program.getAddressFactory().getAddress(address_str)
        if address is None:
            print "Warning: Invalid address {}".format(address_str)
            continue

        code_unit = listing.getCodeUnitAt(address)
        if code_unit:
            # Set PRE comment (appears above the instruction, visible in decompiler)
            code_unit.setComment(CodeUnit.PRE_COMMENT, comment)
            print "Added PRE comment at address {}: {}".format(address_str, comment)
        else:
            print "Warning: No code unit found at address {}".format(address_str)

    print "Line comments have been applied to both assembly listing and decompiled function."

def apply_explanation(func, explanation):
    # Apply explanation as comment
    func.setComment(explanation)
    print "Added explanation as comment to the function."

def prepare_prompt(code, variables, action='rename_retype', callers_code=None):
    """
    Prepares a prompt with the given code and variables for AI interaction.

    Args:
        code (str): The code being analyzed or modified.
        variables (list): A list of variables involved in the analysis.
        action (str): The type of action, e.g., 'rename_retype', 'line_comments'.
        callers_code (dict, optional): Code of functions calling the analyzed function.

    Returns:
        str: The generated prompt.
    """
    # Fetch the prompt template based on the action
    prompt_template = PROMPTS.get(action)
    
    if not prompt_template:
        return None  # Invalid action

    prompt = prompt_template

    if callers_code:
        prompt += "### Additional Context: Callers' Code\n"
        for caller_name, caller_code in callers_code.items():
            prompt += "#### Caller: {}\n\n{}\n\n\n".format(caller_name, caller_code)

    prompt += "### Code:\n\n{}\n\n".format(code)

    # Include variables only if action is not 'line_comments'
    if action != 'line_comments':
        prompt += "### Variables:\n\n{}\n\n".format(json.dumps(variables, indent=2))

    return prompt

def format_new_type(type_str):
    """
    Fixes the formatting of pointer types by ensuring there is a space before each '*' character.
    
    Args:
        type_str (str): The original type string, potentially containing pointers.
        
    Returns:
        str: The formatted type string with spaces before '*' characters.
    """
    # Use regex to find '*' characters not preceded by a space and add a space before them
    fixed_type = re.sub(r'(?<!\s)\*', ' *', type_str)
    
    # Ensure that multiple '*' are properly spaced (e.g., "char**" -> "char * *")
    # This handles cases like "char**", "char ***", etc.
    fixed_type = re.sub(r'\*\*+', lambda m: ' ' + ' *' * len(m.group()), fixed_type)
    
    # Remove any redundant spaces that may have been introduced
    fixed_type = re.sub(r'\s+', ' ', fixed_type).strip()
    
    return fixed_type