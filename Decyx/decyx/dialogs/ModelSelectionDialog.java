package decyx.dialogs;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Dialog for selecting the Claude model to use.
 */
public class ModelSelectionDialog extends JFrame {

    private final List<String> models;
    private String selectedModel;
    private final Runnable onComplete;
    private JComboBox<String> modelComboBox;

    public ModelSelectionDialog(List<String> models, int defaultIndex, Runnable onComplete) {
        super("Select Claude Model");
        this.models = models;
        this.onComplete = onComplete;
        initUI(defaultIndex);
    }

    private void initUI(int defaultIndex) {
        try {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

            addInstructionLabel(panel);
            addModelComboBox(panel, defaultIndex);
            addButtons(panel);

            getContentPane().add(new JScrollPane(panel), BorderLayout.CENTER);
            setSize(300, 150);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setVisible(true);
        } catch (Exception e) {
            System.out.println("Error initializing ModelSelectionDialog UI: " + e.getMessage());
        }
    }

    private void addInstructionLabel(JPanel panel) {
        JLabel instructionLabel = new JLabel("Select the Claude model to use:");
        instructionLabel.setToolTipText("Choose the desired Claude model");
        panel.add(instructionLabel);
    }

    private void addModelComboBox(JPanel panel, int defaultIndex) {
        modelComboBox = new JComboBox<>(models.toArray(new String[0]));
        modelComboBox.setSelectedIndex(defaultIndex);
        modelComboBox.setToolTipText("Select a Claude model from the dropdown");
        panel.add(modelComboBox);
    }

    private void addButtons(JPanel panel) {
        JPanel buttonPanel = new JPanel();
        JButton okButton = new JButton("OK");
        okButton.addActionListener(e -> ok());
        okButton.setToolTipText("Confirm model selection");
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancel());
        cancelButton.setToolTipText("Cancel model selection");
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    private void ok() {
        selectedModel = (String) modelComboBox.getSelectedItem();
        onComplete.run();
        dispose();
    }

    private void cancel() {
        selectedModel = null;
        onComplete.run();
        dispose();
    }

    public String getSelectedModel() {
        return selectedModel;
    }

    /**
     * Displays the dialog and waits for user interaction.
     *
     * @param models list of available Claude models
     * @return the selected model name or null if cancelled
     */
    public static String showDialog(List<String> models) {
        CountDownLatch latch = new CountDownLatch(1);
        ModelSelectionDialog[] dialogHolder = new ModelSelectionDialog[1];

        SwingUtilities.invokeLater(() -> {
            dialogHolder[0] = new ModelSelectionDialog(models, 0, latch::countDown);
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return dialogHolder[0] != null ? dialogHolder[0].getSelectedModel() : null;
    }
}
