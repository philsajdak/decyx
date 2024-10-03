# decompiler.py

import re
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import ClangStatement
from config import GLOBAL_VARIABLE_PATTERNS

def initialize_decompiler():
    """
    Initializes and configures the Ghidra Decompiler interface.

    Returns:
        DecompInterface: An initialized and configured DecompInterface object.
    """
    decomp_interface = DecompInterface()
    options = DecompileOptions()
    decomp_interface.setOptions(options)
    decomp_interface.toggleCCode(True)
    decomp_interface.toggleSyntaxTree(True)
    return decomp_interface

def traverse_clang_node(node, callback):
    """
    Recursively traverses a Clang AST node, applying a callback to each node.

    Args:
        node (ClangNode): The current Clang AST node.
        callback (function): The function to apply to each node.
    """
    callback(node)
    for i in range(node.numChildren()):
        child = node.Child(i)
        traverse_clang_node(child, callback)

def annotate_code_with_addresses(code_markup):
    """
    Annotates the decompiled code with addresses from the Clang AST.

    Args:
        code_markup (ClangNode): The root node of the Clang AST.

    Returns:
        str: The annotated decompiled code as a single string.
    """
    annotated_lines = []

    def collect_lines(node):
        if isinstance(node, ClangStatement):
            address = node.getMinAddress()
            code_line = node.toString()
            if address:
                annotated_line = "// Address: {}\n{}".format(address, code_line)
            else:
                annotated_line = code_line
            annotated_lines.append(annotated_line)

    traverse_clang_node(code_markup, collect_lines)
    return '\n'.join(annotated_lines)

def find_global_variables(decompiled_code):
    """
    Identifies global variables in the decompiled code based on naming patterns defined in config.py.
    Args:
        decompiled_code (str): The decompiled C code of the function.
    Returns:
        set: A set of global variable names found in the code.
    """
    global_variables = set()
    for pattern in GLOBAL_VARIABLE_PATTERNS:
        global_variables.update(re.findall(pattern, decompiled_code))
    return global_variables
    
def extract_global_variables(global_vars, currentProgram):
    """
    Extracts information about global variables.
    Args:
        global_vars (set): Set of global variable names.
        currentProgram (Program): The current Ghidra program.
    Returns:
        list: A list of dictionaries, each representing a global variable with its details.
    """
    global_var_info = []
    symbolTable = currentProgram.getSymbolTable()
    
    for global_var in global_vars:
        symbols = symbolTable.getGlobalSymbols(global_var)
        if symbols and len(symbols) > 0:
            symbol = symbols[0]  # Get the first symbol if multiple exist
            if symbol.getSymbolType() == SymbolType.LABEL:
                addr = symbol.getAddress()
                data = currentProgram.getListing().getDataAt(addr)
                data_type = str(data.getDataType()) if data else "unknown"
            else:
                data_type = str(symbol.getObject().getDataType())
        else:
            data_type = "unknown"
        
        global_var_info.append({
            "old_name": global_var,
            "old_type": data_type,
            "storage": "global"
        })
    
    return global_var_info

def extract_variables(func, decompiled_code, currentProgram):
    """
    Extracts all relevant variables from the function, including parameters, local variables, and globals.
    Args:
        func (Function): The function object from Ghidra.
        decompiled_code (str): The decompiled C code of the function.
        currentProgram (Program): The current Ghidra program.
    Returns:
        list: A list of dictionaries, each representing a variable with its details.
    """
    all_vars = []
    
    # Extract parameters
    for param in func.getParameters():
        all_vars.append({
            "old_name": param.getName(),
            "old_type": str(param.getDataType()),
            "storage": str(param.getVariableStorage())
        })
    
    # Extract local variables
    for local_var in func.getLocalVariables():
        all_vars.append({
            "old_name": local_var.getName(),
            "old_type": str(local_var.getDataType()),
            "storage": str(local_var.getVariableStorage())
        })
    
    # Identify global variables referenced in the decompiled code
    global_vars = find_global_variables(decompiled_code)
    
    # Extract global variables
    all_vars.extend(extract_global_variables(global_vars, currentProgram))
    
    # Filter out variables with 'HASH' in their storage to exclude irrelevant entries
    return [var for var in all_vars if 'HASH' not in var['storage']]

def decompile_function(func, current_program, monitor, annotate_addresses=False):
    """
    Decompiles a given function to retrieve its C code and variable information.

    Args:
        func (Function): The function to decompile.
        current_program (Program): The current program context in Ghidra.
        monitor (TaskMonitor): The monitor object for progress tracking.
        annotate_addresses (bool): Whether to annotate the decompiled code with addresses.

    Returns:
        tuple: A tuple containing the decompiled code as a string and a list of variables.
               Returns (None, None) if decompilation fails.
    """
    decomp_interface = initialize_decompiler()
    decomp_interface.openProgram(current_program)

    try:
        results = decomp_interface.decompileFunction(func, 60, monitor)
        if not results.decompileCompleted():
            print "Decompilation failed for function at {}".format(func.getEntryPoint())
            return None, None

        print "Decompilation completed successfully."
        decompiled_function = results.getDecompiledFunction()
        high_func = results.getHighFunction()
        code_markup = results.getCCodeMarkup()

        # Commit any local names to the database
        HighFunctionDBUtil.commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED)

        if annotate_addresses:
            decompiled_code_str = annotate_code_with_addresses(code_markup)
        else:
            decompiled_code_str = decompiled_function.getC()

        variables = extract_variables(func, decompiled_code_str, current_program)
        return decompiled_code_str, variables

    except Exception as e:
        print "Exception during decompilation: {}".format(e)
        return None, None
    finally:
        decomp_interface.dispose()

def decompile_callers(callers, current_program, monitor):
    """
    Decompiles a list of caller functions to provide additional context.

    Args:
        callers (list): A list of caller Function objects.
        current_program (Program): The current program context in Ghidra.
        monitor (TaskMonitor): The monitor object for progress tracking.

    Returns:
        dict: A dictionary mapping caller names to their decompiled code or error messages.
    """
    decomp_interface = initialize_decompiler()
    decomp_interface.openProgram(current_program)
    
    callers_code = {}
    total_callers = len(callers)
    
    try:
        for index, caller in enumerate(callers):
            if monitor.isCancelled():
                print "Decompilation cancelled by user."
                break
            progress_percentage = int(((index + 1) / float(total_callers)) * 100)
            monitor.setProgress(progress_percentage)
            try:
                results = decomp_interface.decompileFunction(caller, 60, monitor)
                if results.decompileCompleted():
                    decompiled_code = results.getDecompiledFunction().getC()
                    callers_code[caller.getName()] = decompiled_code
                    print "Decompiled caller '{}' successfully.".format(caller.getName())
                else:
                    callers_code[caller.getName()] = "Decompilation failed."
                    print "Decompilation failed for caller '{}'.".format(caller.getName())
            except Exception as e:
                callers_code[caller.getName()] = "Exception during decompilation: {}".format(e)
                print "Exception during decompilation of caller '{}': {}".format(caller.getName(), e)
    finally:
        decomp_interface.dispose()
    
    return callers_code