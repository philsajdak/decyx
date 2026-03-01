package decyx.dialogs;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import decyx.DecyxConfig;
import decyx.SuggestionUtils;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Dialog for displaying and applying suggestions from the Claude API.
 */
public class SuggestionDialog extends JFrame {

    private final JsonObject suggestions;
    private final List<Map<String, String>> variablesWithOldTypes;
    private final PluginTool tool;
    private final Runnable onComplete;
    private JsonObject selectedSuggestions;
    private final List<Boolean> typeValidity = new ArrayList<>();
    private DefaultTableModel tableModel;
    private JTable variableTable;
    private JCheckBox funcCheckbox;
    private JTextField funcNameField;
    private JTextArea explanationArea;

    public SuggestionDialog(JsonObject suggestions, List<Map<String, String>> variablesWithOldTypes,
                             PluginTool tool, Runnable onComplete) {
        super("Claude Suggestions");
        this.suggestions = suggestions;
        this.variablesWithOldTypes = variablesWithOldTypes;
        this.tool = tool;
        this.onComplete = onComplete;
        this.selectedSuggestions = null;
        initUI();
    }

    private void initUI() {
        try {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

            addFunctionNamePanel(panel);
            addVariableTable(panel);
            addSummaryLabel(panel);
            addButtonPanel(panel);
            addExplanationArea(panel);
            addApplyCancelButtons(panel);

            getContentPane().add(panel);
            setSize(DecyxConfig.DEFAULT_WINDOW_WIDTH, DecyxConfig.DEFAULT_WINDOW_HEIGHT);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setVisible(true);
        } catch (Exception e) {
            System.out.println("Error initializing SuggestionDialog UI: " + e.getMessage());
        }
    }

    private void addFunctionNamePanel(JPanel panel) {
        JPanel funcPanel = new JPanel();
        funcPanel.setLayout(new BoxLayout(funcPanel, BoxLayout.X_AXIS));
        funcCheckbox = new JCheckBox("Rename function to:");
        funcCheckbox.setSelected(true);
        funcCheckbox.setToolTipText("Check to rename the function");

        String funcName = suggestions.has("function_name") ? suggestions.get("function_name").getAsString() : "";
        funcNameField = new JTextField(funcName, 20);
        funcNameField.setMaximumSize(new Dimension(200, 25));
        funcNameField.setToolTipText("Enter the new function name here");

        funcPanel.add(funcCheckbox);
        funcPanel.add(funcNameField);
        panel.add(funcPanel);
    }

    private void addVariableTable(JPanel panel) {
        String[] columnNames = {"Old Name", "New Name", "Old Type", "New Type", "Rename", "Retype"};
        tableModel = new DefaultTableModel(new Object[0][], columnNames) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 4 || columnIndex == 5) {
                    return Boolean.class;
                }
                return String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 4 || column == 5;
            }
        };
        variableTable = new JTable(tableModel);
        populateVariableTable();
        setTableColumnWidths();
        setTableRenderers();
        JScrollPane tableScroll = new JScrollPane(variableTable);
        tableScroll.setPreferredSize(new Dimension(700, 300));
        panel.add(tableScroll);
    }

    private void populateVariableTable() {
        // Build lookup from old_name to old_type
        java.util.HashMap<String, String> oldNameToType = new java.util.HashMap<>();
        for (Map<String, String> var : variablesWithOldTypes) {
            oldNameToType.put(var.get("old_name"), var.get("old_type"));
        }

        JsonArray vars = suggestions.getAsJsonArray("variables");
        for (int i = 0; i < vars.size(); i++) {
            JsonObject var = vars.get(i).getAsJsonObject();
            String oldName = var.get("old_name").getAsString();
            String newName = var.has("new_name") ? var.get("new_name").getAsString() : "";
            String oldType = oldNameToType.getOrDefault(oldName, "unknown");
            String newType = SuggestionUtils.formatNewType(var.has("new_type") ? var.get("new_type").getAsString() : "");

            boolean typeValid = SuggestionUtils.findDataTypeByName(newType, tool) != null;
            typeValidity.add(typeValid);

            tableModel.addRow(new Object[]{oldName, newName, oldType, newType, true, typeValid});
        }
    }

    private void setTableColumnWidths() {
        int[] columnWidths = {100, 100, 100, 100, 60, 60};
        for (int i = 0; i < columnWidths.length; i++) {
            variableTable.getColumnModel().getColumn(i).setPreferredWidth(columnWidths[i]);
        }
    }

    private void setTableRenderers() {
        try {
            BoldRenderer boldRenderer = new BoldRenderer();
            NewTypeCellRenderer newTypeRenderer = new NewTypeCellRenderer(typeValidity);

            variableTable.getColumnModel().getColumn(1).setCellRenderer(boldRenderer);
            variableTable.getColumnModel().getColumn(3).setCellRenderer(newTypeRenderer);
        } catch (Exception e) {
            System.out.println("Error setting table renderers: " + e.getMessage());
        }
    }

    private void addSummaryLabel(JPanel panel) {
        try {
            int totalVars = variablesWithOldTypes.size();
            JsonArray vars = suggestions.getAsJsonArray("variables");
            int numSuggestedRenames = 0;
            for (int i = 0; i < vars.size(); i++) {
                JsonObject var = vars.get(i).getAsJsonObject();
                String oldName = var.get("old_name").getAsString();
                String newName = var.has("new_name") ? var.get("new_name").getAsString() : oldName;
                if (!oldName.equals(newName)) {
                    numSuggestedRenames++;
                }
            }

            int numValidRetypes = 0;
            int numInvalidRetypes = 0;
            for (boolean valid : typeValidity) {
                if (valid) {
                    numValidRetypes++;
                } else {
                    numInvalidRetypes++;
                }
            }
            int totalRetypes = numValidRetypes + numInvalidRetypes;

            String summaryHtml = "<html><b>Summary:</b><br>" +
                "Rename suggestions: " + numSuggestedRenames + "/" + totalVars + " total variables<br>" +
                "Retype suggestions: " + numValidRetypes + "/" + totalRetypes + " valid, " +
                numInvalidRetypes + "/" + totalRetypes + " invalid</html>";

            JLabel summaryLabel = new JLabel(summaryHtml);
            panel.add(summaryLabel);
        } catch (Exception e) {
            System.out.println("Error adding summary label: " + e.getMessage());
        }
    }

    private void addButtonPanel(JPanel panel) {
        JPanel buttonPanel = new JPanel();
        String[][] buttons = {
            {"Select All Renames", "4", "true"},
            {"Unselect All Renames", "4", "false"},
            {"Select All Retypes", "5", "true"},
            {"Unselect All Retypes", "5", "false"}
        };

        for (String[] btnDef : buttons) {
            JButton button = new JButton(btnDef[0]);
            int col = Integer.parseInt(btnDef[1]);
            boolean val = Boolean.parseBoolean(btnDef[2]);
            button.addActionListener(e -> selectAll(col, val));
            button.setToolTipText(btnDef[0]);
            buttonPanel.add(button);
        }
        panel.add(buttonPanel);
    }

    private void selectAll(int column, boolean value) {
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            tableModel.setValueAt(value, row, column);
        }
    }

    private void addExplanationArea(JPanel panel) {
        if (suggestions.has("explanation") && !suggestions.get("explanation").isJsonNull()) {
            String explanation = suggestions.get("explanation").getAsString();
            if (!explanation.isEmpty()) {
                panel.add(new JLabel("Explanation:"));
                explanationArea = new JTextArea(explanation, 5, 30);
                explanationArea.setEditable(false);
                explanationArea.setLineWrap(true);
                explanationArea.setWrapStyleWord(true);
                explanationArea.setToolTipText("Explanation provided by the API");
                panel.add(new JScrollPane(explanationArea));
            }
        }
    }

    private void addApplyCancelButtons(JPanel panel) {
        JPanel bottomButtonPanel = new JPanel();
        JButton applyButton = new JButton("Apply Selected");
        applyButton.addActionListener(e -> applyChanges());
        applyButton.setToolTipText("Apply the selected suggestions");
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancel());
        cancelButton.setToolTipText("Cancel without applying changes");
        bottomButtonPanel.add(applyButton);
        bottomButtonPanel.add(cancelButton);
        panel.add(bottomButtonPanel);
    }

    private void applyChanges() {
        try {
            selectedSuggestions = new JsonObject();

            // Function name
            if (funcCheckbox.isSelected()) {
                selectedSuggestions.addProperty("function_name", funcNameField.getText());
            } else {
                selectedSuggestions.add("function_name", JsonNull.INSTANCE);
            }

            // Variables
            JsonArray selectedVars = new JsonArray();
            for (int row = 0; row < tableModel.getRowCount(); row++) {
                String oldName = (String) tableModel.getValueAt(row, 0);
                String newName = (String) tableModel.getValueAt(row, 1);
                String newType = (String) tableModel.getValueAt(row, 3);
                boolean rename = Boolean.TRUE.equals(tableModel.getValueAt(row, 4));
                boolean retype = Boolean.TRUE.equals(tableModel.getValueAt(row, 5));

                if (rename || retype) {
                    JsonObject varSuggestion = new JsonObject();
                    varSuggestion.addProperty("old_name", oldName);
                    if (rename) {
                        varSuggestion.addProperty("new_name", newName);
                    }
                    if (retype) {
                        varSuggestion.addProperty("new_type", newType);
                    }
                    selectedVars.add(varSuggestion);
                } else {
                    selectedVars.add(JsonNull.INSTANCE);
                }
            }
            selectedSuggestions.add("variables", selectedVars);

            // Explanation
            if (explanationArea != null) {
                selectedSuggestions.addProperty("explanation", explanationArea.getText());
            } else {
                selectedSuggestions.add("explanation", JsonNull.INSTANCE);
            }

            onComplete.run();
            dispose();
        } catch (Exception e) {
            System.out.println("Error applying changes: " + e.getMessage());
        }
    }

    private void cancel() {
        selectedSuggestions = null;
        onComplete.run();
        dispose();
    }

    public JsonObject getSelectedSuggestions() {
        return selectedSuggestions;
    }

    /**
     * Displays the dialog and waits for user interaction.
     *
     * @param suggestions          the suggestions from Claude API
     * @param variablesWithOldTypes list of variables with their old types
     * @param tool                 the Ghidra tool instance
     * @return the selected suggestions or null if cancelled
     */
    public static JsonObject showDialog(JsonObject suggestions, List<Map<String, String>> variablesWithOldTypes,
                                         PluginTool tool) {
        CountDownLatch latch = new CountDownLatch(1);
        SuggestionDialog[] dialogHolder = new SuggestionDialog[1];

        SwingUtilities.invokeLater(() -> {
            dialogHolder[0] = new SuggestionDialog(suggestions, variablesWithOldTypes, tool, latch::countDown);
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return dialogHolder[0] != null ? dialogHolder[0].getSelectedSuggestions() : null;
    }

    // --- Custom cell renderers ---

    /**
     * Custom renderer to display text in bold font.
     */
    static class BoldRenderer extends DefaultTableCellRenderer {
        private Font boldFont;

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                        boolean isSelected, boolean hasFocus, int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (boldFont == null) {
                boldFont = component.getFont().deriveFont(Font.BOLD);
            }
            component.setFont(boldFont);
            return component;
        }
    }

    /**
     * Custom renderer to display new type cells in bold and color-coded based on validity.
     */
    static class NewTypeCellRenderer extends DefaultTableCellRenderer {
        private Font boldFont;
        private final List<Boolean> typeValidity;

        NewTypeCellRenderer(List<Boolean> typeValidity) {
            this.typeValidity = typeValidity;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                        boolean isSelected, boolean hasFocus, int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (boldFont == null) {
                boldFont = component.getFont().deriveFont(Font.BOLD);
            }
            component.setFont(boldFont);
            if (row < typeValidity.size() && !typeValidity.get(row)) {
                component.setForeground(Color.RED);
            } else {
                component.setForeground(table.getForeground());
            }
            return component;
        }
    }
}
