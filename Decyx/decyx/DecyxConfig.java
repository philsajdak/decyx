package decyx;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Configuration constants for the Decyx Ghidra extension.
 */
public final class DecyxConfig {

    private DecyxConfig() {}

    public static final String CLAUDE_API_URL = "https://api.anthropic.com/v1/messages";
    public static final List<String> CLAUDE_MODELS = Arrays.asList("claude-sonnet-4-20250514");

    /** Set to true to skip prompt confirmation windows. */
    public static final boolean SKIP_PROMPT_CONFIRMATION = false;

    /** Default window dimensions. */
    public static final int DEFAULT_WINDOW_WIDTH = 750;
    public static final int DEFAULT_WINDOW_HEIGHT = 500;

    /** Prompt templates keyed by action name. */
    public static final Map<String, String> PROMPTS = new HashMap<>();

    static {
        PROMPTS.put("rename_retype",
            "Analyze the following decompiled C function code and its variables. Provide the following:\n" +
            "1. A suggested concise and descriptive name for the function.\n" +
            "2. Suggested new names and data types for each variable, including globals if applicable.\n\n" +
            "Respond with a JSON object containing 'function_name' and 'variables' fields. " +
            "The 'variables' field should be an array of objects, each containing 'old_name', 'new_name', and 'new_type'.\n\n");

        PROMPTS.put("explanation",
            "Provide a brief detailed explanation of the following decompiled C function code and its variables. " +
            "The explanation should be in-depth but concise, incorporating any meaningful names where applicable.\n\n" +
            "Respond with a plain text explanation, without any formatting.\n\n");

        PROMPTS.put("line_comments",
            "Analyze the following decompiled C function code annotated with addresses. Provide concise, meaningful comments " +
            "**only** for important lines or sections of the code. Focus on explaining the purpose or significance of each " +
            "important operation.\n\n" +
            "Respond with a JSON object where each key is the address (as a string) and the value is the suggested " +
            "comment for that line. Only include addresses that need comments.\n\n" +
            "Example format:\n" +
            "{\n" +
            "  \"0x401000\": \"Initialize the device object\",\n" +
            "  \"0x401010\": \"Check OS version for compatibility\",\n" +
            "  \"0x401020\": \"Create symbolic link for the device\"\n" +
            "}\n\n");
    }

    /** Global variable patterns (Ghidra defaults + user-renamed). */
    public static final List<Pattern> GLOBAL_VARIABLE_PATTERNS = Arrays.asList(
        Pattern.compile("\\bDAT_[0-9a-fA-F]+\\b"),
        Pattern.compile("\\bg_\\w+\\b")
    );
}
