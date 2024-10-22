# config.py

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODELS = ["claude-3-5-sonnet-latest"]

# Set to True to enable fast selection and skip prompt confirmation windows
SKIP_PROMPT_CONFIRMATION = False

# Default window dimensions
DEFAULT_WINDOW_WIDTH = 750
DEFAULT_WINDOW_HEIGHT = 500

# Prompt Templates
PROMPTS = {
    "rename_retype": (
        "Analyze the following decompiled C function code and its variables. Provide the following:\n"
        "1. A suggested concise and descriptive name for the function.\n"
        "2. Suggested new names and data types for each variable, including globals if applicable.\n\n"
        "Respond with a JSON object containing 'function_name' and 'variables' fields. The 'variables' field should be an array of objects, each containing 'old_name', 'new_name', and 'new_type'.\n\n"
    ),
    "explanation": (
        "Provide a brief detailed explanation of the following decompiled C function code and its variables. "
        "The explanation should be in-depth but concise, incorporating any meaningful names where applicable.\n\n"
        "Respond with a plain text explanation, without any formatting.\n\n"
    ),
    "line_comments": (
        "Analyze the following decompiled C function code annotated with addresses. Provide concise, meaningful comments "
        "**only** for important lines or sections of the code. Focus on explaining the purpose or significance of each "
        "important operation.\n\n"
        "Respond with a JSON object where each key is the address (as a string) and the value is the suggested "
        "comment for that line. Only include addresses that need comments.\n\n"
        "Example format:\n"
        "{\n"
        "  \"0x401000\": \"Initialize the device object\",\n"
        "  \"0x401010\": \"Check OS version for compatibility\",\n"
        "  \"0x401020\": \"Create symbolic link for the device\"\n"
        "}\n\n"
    )
}

# Global variable patterns
GLOBAL_VARIABLE_PATTERNS = [
    r'\bDAT_[0-9a-fA-F]+\b', # Default Ghidra pattern
    r'\bg_\w+\b' # Most likely renamed by our script
]