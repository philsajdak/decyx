package decyx;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles communication with the Anthropic Claude API.
 */
public class ClaudeApi {

    /**
     * Sends a POST request to the specified URL.
     *
     * @param urlStr  the URL to send the request to
     * @param headers HTTP headers to include
     * @param body    the JSON body as a string
     * @return the response body as a string, or null on failure
     */
    public static String sendRequest(String urlStr, Map<String, String> headers, String body) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(urlStr);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);

            for (Map.Entry<String, String> header : headers.entrySet()) {
                connection.setRequestProperty(header.getKey(), header.getValue());
            }

            try (OutputStream os = connection.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = connection.getResponseCode();
            InputStream inputStream;
            if (responseCode >= 200 && responseCode < 300) {
                inputStream = connection.getInputStream();
            } else {
                inputStream = connection.getErrorStream();
                String errorContent = readStream(inputStream);
                System.out.println("Error: HTTP response code " + responseCode);
                System.out.println("Error message: " + errorContent);
                return null;
            }

            return readStream(inputStream);

        } catch (IOException e) {
            System.out.println("Failed to reach server: " + e.getMessage());
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String readStream(InputStream stream) throws IOException {
        if (stream == null) {
            return null;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    /**
     * Parses a JSON object from within a string that may contain surrounding text.
     *
     * @param content the response content
     * @return the parsed JsonObject, or null on failure
     */
    public static JsonObject parseJsonResponse(String content) {
        int jsonStart = content.indexOf('{');
        int jsonEnd = content.lastIndexOf('}') + 1;
        if (jsonStart != -1 && jsonEnd > jsonStart) {
            String jsonStr = content.substring(jsonStart, jsonEnd);
            try {
                return JsonParser.parseString(jsonStr).getAsJsonObject();
            } catch (JsonSyntaxException e) {
                System.out.println("Failed to parse JSON from Claude's response: " + e.getMessage());
            }
        } else {
            System.out.println("No JSON object found in Claude's response");
        }
        return null;
    }

    /**
     * Sends a prompt to the Claude API and returns the parsed response.
     *
     * @param prompt        the prompt to send
     * @param apiKey        the Anthropic API key
     * @param model         the model name to use
     * @param monitor       task monitor for status messages
     * @param isExplanation if true, return the raw text instead of parsed JSON
     * @return a JsonObject with the parsed suggestions, a String explanation, or null on failure
     */
    public static Object getResponseFromClaude(String prompt, String apiKey, String model,
                                               TaskMonitor monitor, boolean isExplanation) {
        try {
            monitor.setMessage("Sending request to Claude API...");

            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("x-api-key", apiKey);
            headers.put("anthropic-version", "2023-06-01");

            JsonObject data = new JsonObject();
            data.addProperty("model", model);

            JsonArray messages = new JsonArray();
            JsonObject message = new JsonObject();
            message.addProperty("role", "user");
            message.addProperty("content", prompt);
            messages.add(message);
            data.add("messages", messages);

            data.addProperty("max_tokens", 2000);
            data.addProperty("temperature", 0.2);
            data.addProperty("top_p", 1.0);
            data.addProperty("top_k", 30);

            System.out.println("Sending request to Claude API...");
            monitor.setMessage("Waiting for response from Claude API...");

            String responseBody = sendRequest(DecyxConfig.CLAUDE_API_URL, headers, data.toString());

            if (responseBody != null) {
                System.out.println("Received response from Claude API.");
                JsonObject responseJson = JsonParser.parseString(responseBody).getAsJsonObject();
                JsonArray contentArray = responseJson.getAsJsonArray("content");
                String contentText = contentArray.get(0).getAsJsonObject().get("text").getAsString();

                if (isExplanation) {
                    return contentText.trim();
                } else {
                    return parseJsonResponse(contentText);
                }
            }

            return null;

        } catch (Exception e) {
            System.out.println("Exception in getResponseFromClaude: " + e.getMessage());
            return null;
        } finally {
            monitor.setMessage("");
        }
    }
}
