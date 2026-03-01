package decyx.dialogs;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Dialog for selecting the actions to perform (rename/retype, explanation, line comments).
 */
public class ActionSelectionDialog extends JFrame {

    private final List<String> selectedActions = new ArrayList<>();
    private final Runnable onComplete;
    private JCheckBox renameRetypeCheckbox;
    private JCheckBox explanationCheckbox;
    private JCheckBox lineCommentsCheckbox;

    public ActionSelectionDialog(Runnable onComplete) {
        super("Select Actions to Perform");
        this.onComplete = onComplete;
        initUI();
    }

    private void initUI() {
        try {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

            addInstructionLabel(panel);
            addCheckboxes(panel);
            addButtons(panel);

            getContentPane().add(panel, BorderLayout.CENTER);
            setSize(300, 200);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setVisible(true);
        } catch (Exception e) {
            System.out.println("Error initializing ActionSelectionDialog UI: " + e.getMessage());
        }
    }

    private void addInstructionLabel(JPanel panel) {
        JLabel instructionLabel = new JLabel("Select the actions you want to perform:");
        instructionLabel.setToolTipText("Choose the desired actions");
        panel.add(instructionLabel);
    }

    private void addCheckboxes(JPanel panel) {
        renameRetypeCheckbox = new JCheckBox("Rename and Retype Variables");
        renameRetypeCheckbox.setSelected(true);
        renameRetypeCheckbox.setToolTipText("Rename variables and update their types");
        panel.add(renameRetypeCheckbox);

        explanationCheckbox = new JCheckBox("Get Function Explanation");
        explanationCheckbox.setSelected(false);
        explanationCheckbox.setToolTipText("Obtain explanations for functions");
        panel.add(explanationCheckbox);

        lineCommentsCheckbox = new JCheckBox("Add Line Comments");
        lineCommentsCheckbox.setSelected(false);
        lineCommentsCheckbox.setToolTipText("Add comments to lines of code");
        panel.add(lineCommentsCheckbox);
    }

    private void addButtons(JPanel panel) {
        JPanel buttonPanel = new JPanel();
        JButton okButton = new JButton("OK");
        okButton.addActionListener(e -> ok());
        okButton.setToolTipText("Confirm action selection");
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancel());
        cancelButton.setToolTipText("Cancel action selection");
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    private void ok() {
        selectedActions.clear();
        if (renameRetypeCheckbox.isSelected()) {
            selectedActions.add("rename_retype");
        }
        if (explanationCheckbox.isSelected()) {
            selectedActions.add("explanation");
        }
        if (lineCommentsCheckbox.isSelected()) {
            selectedActions.add("line_comments");
        }
        onComplete.run();
        dispose();
    }

    private void cancel() {
        selectedActions.clear();
        onComplete.run();
        dispose();
    }

    public List<String> getSelectedActions() {
        return selectedActions;
    }

    /**
     * Displays the dialog and waits for user interaction.
     *
     * @return the list of selected action strings
     */
    public static List<String> showDialog() {
        CountDownLatch latch = new CountDownLatch(1);
        ActionSelectionDialog[] dialogHolder = new ActionSelectionDialog[1];

        SwingUtilities.invokeLater(() -> {
            dialogHolder[0] = new ActionSelectionDialog(latch::countDown);
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return dialogHolder[0] != null ? dialogHolder[0].getSelectedActions() : new ArrayList<>();
    }
}
