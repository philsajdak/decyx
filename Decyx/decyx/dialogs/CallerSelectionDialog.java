package decyx.dialogs;

import decyx.DecompilerHelper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Dialog for selecting which caller functions' code to include for additional context.
 */
public class CallerSelectionDialog extends JFrame {

    private final List<Function> callers;
    private final Program currentProgram;
    private final TaskMonitor monitor;
    private final Runnable onComplete;
    private final List<Function> selectedCallers = new ArrayList<>();
    private final List<JCheckBox> callerCheckboxes = new ArrayList<>();
    private JTextArea previewTextArea;
    private JLabel previewLabel;

    public CallerSelectionDialog(List<Function> callers, Program currentProgram,
                                  TaskMonitor monitor, Runnable onComplete) {
        super("Select Callers to Include");
        this.callers = callers;
        this.currentProgram = currentProgram;
        this.monitor = monitor;
        this.onComplete = onComplete;
        initUI();
    }

    private void initUI() {
        try {
            JPanel panel = new JPanel(new BorderLayout());

            addCallersPanel(panel);
            addPreviewPanel(panel);
            addButtonsPanel(panel);

            getContentPane().add(panel);
            setSize(800, 400);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setVisible(true);
        } catch (Exception e) {
            System.out.println("Error initializing CallerSelectionDialog UI: " + e.getMessage());
        }
    }

    private void addCallersPanel(JPanel panel) {
        JPanel callersPanel = new JPanel();
        callersPanel.setLayout(new BoxLayout(callersPanel, BoxLayout.Y_AXIS));

        for (Function caller : callers) {
            JCheckBox checkbox = new JCheckBox(caller.getName());
            checkbox.setSelected(false);
            checkbox.setToolTipText("Include code from caller: " + caller.getName());
            checkbox.addActionListener(e -> updatePreview(caller, checkbox.isSelected()));
            callerCheckboxes.add(checkbox);
            callersPanel.add(checkbox);
        }

        JScrollPane scrollCallers = new JScrollPane(callersPanel);
        scrollCallers.setPreferredSize(new Dimension(200, 300));
        panel.add(scrollCallers, BorderLayout.WEST);
    }

    private void updatePreview(Function caller, boolean selected) {
        try {
            if (selected) {
                DecompilerHelper.DecompileResult result =
                    DecompilerHelper.decompileFunction(caller, currentProgram, monitor, false);
                if (result != null && result.code != null) {
                    int codeLength = result.code.length();
                    updatePreviewLabel(codeLength);
                    setPreviewText(result.code);
                } else {
                    setPreviewText("Decompilation failed or no code available.");
                    updatePreviewLabel(0);
                }
            } else {
                setPreviewText("Select a caller to see its decompiled code preview.");
                updatePreviewLabel(0);
            }
        } catch (Exception e) {
            System.out.println("Error updating preview: " + e.getMessage());
        }
    }

    private void addPreviewPanel(JPanel panel) {
        JPanel previewPanel = new JPanel(new BorderLayout());
        previewLabel = new JLabel("Caller Function Preview:");
        previewPanel.add(previewLabel, BorderLayout.NORTH);

        previewTextArea = new JTextArea();
        previewTextArea.setEditable(false);
        previewTextArea.setLineWrap(true);
        previewTextArea.setWrapStyleWord(true);
        previewTextArea.setText("Select a caller to see its decompiled code preview.");
        previewTextArea.setToolTipText("Decompiled code preview of the selected caller");
        previewTextArea.setCaretPosition(0);
        JScrollPane scrollPreview = new JScrollPane(previewTextArea);
        previewPanel.add(scrollPreview, BorderLayout.CENTER);

        panel.add(previewPanel, BorderLayout.CENTER);
    }

    private void addButtonsPanel(JPanel panel) {
        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.Y_AXIS));

        JPanel selectButtons = new JPanel();
        JButton selectAllButton = new JButton("Select All Callers");
        selectAllButton.addActionListener(e -> selectAll(true));
        selectAllButton.setToolTipText("Select all caller checkboxes");
        JButton unselectAllButton = new JButton("Unselect All Callers");
        unselectAllButton.addActionListener(e -> selectAll(false));
        unselectAllButton.setToolTipText("Unselect all caller checkboxes");
        selectButtons.add(selectAllButton);
        selectButtons.add(unselectAllButton);

        JPanel actionButtons = new JPanel();
        JButton okButton = new JButton("OK");
        okButton.addActionListener(e -> ok());
        okButton.setToolTipText("Confirm selection and proceed");
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancel());
        cancelButton.setToolTipText("Cancel selection");
        actionButtons.add(okButton);
        actionButtons.add(cancelButton);

        buttonsPanel.add(selectButtons);
        buttonsPanel.add(actionButtons);
        panel.add(buttonsPanel, BorderLayout.SOUTH);
    }

    private void setPreviewText(String text) {
        previewTextArea.setText(text);
        previewTextArea.setCaretPosition(0);
    }

    private void updatePreviewLabel(int length) {
        previewLabel.setText("Caller Function Preview (Length: " + length + " characters):");
    }

    private void selectAll(boolean select) {
        for (JCheckBox checkbox : callerCheckboxes) {
            checkbox.setSelected(select);
        }
    }

    private void ok() {
        selectedCallers.clear();
        for (int i = 0; i < callerCheckboxes.size(); i++) {
            if (callerCheckboxes.get(i).isSelected()) {
                selectedCallers.add(callers.get(i));
            }
        }
        onComplete.run();
        dispose();
    }

    private void cancel() {
        selectedCallers.clear();
        onComplete.run();
        dispose();
    }

    public List<Function> getSelectedCallers() {
        return selectedCallers;
    }

    /**
     * Displays the dialog and waits for user interaction.
     *
     * @param callers        list of caller Function objects
     * @param currentProgram the current program context
     * @param monitor        the monitor for progress tracking
     * @return the list of selected caller Function objects
     */
    public static List<Function> showDialog(List<Function> callers, Program currentProgram,
                                             TaskMonitor monitor) {
        CountDownLatch latch = new CountDownLatch(1);
        CallerSelectionDialog[] dialogHolder = new CallerSelectionDialog[1];

        SwingUtilities.invokeLater(() -> {
            dialogHolder[0] = new CallerSelectionDialog(callers, currentProgram, monitor, latch::countDown);
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return dialogHolder[0] != null ? dialogHolder[0].getSelectedCallers() : new ArrayList<>();
    }
}
