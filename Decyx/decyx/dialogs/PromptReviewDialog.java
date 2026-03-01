package decyx.dialogs;

import decyx.DecyxConfig;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.CountDownLatch;

/**
 * Dialog for reviewing and editing the prompt before sending it to the Claude API.
 */
public class PromptReviewDialog extends JFrame {

    private String finalPrompt;
    private final Runnable onComplete;
    private JTextArea promptTextArea;

    public PromptReviewDialog(String prompt, String title, Runnable onComplete) {
        super(title);
        this.finalPrompt = null;
        this.onComplete = onComplete;
        initUI(prompt);
    }

    private void initUI(String prompt) {
        try {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

            addInstructionLabel(panel);
            addPromptTextArea(panel, prompt);
            addButtons(panel);

            getContentPane().add(new JScrollPane(panel), BorderLayout.CENTER);
            setSize(700, 500);
            setLocationRelativeTo(null);
            setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            setVisible(true);
        } catch (Exception e) {
            System.out.println("Error initializing PromptReviewDialog UI: " + e.getMessage());
        }
    }

    private void addInstructionLabel(JPanel panel) {
        JLabel instructionLabel = new JLabel("Review and edit the final prompt before sending to Claude API:");
        instructionLabel.setToolTipText("You can modify the prompt as needed");
        panel.add(instructionLabel);
    }

    private void addPromptTextArea(JPanel panel, String prompt) {
        promptTextArea = new JTextArea(prompt, 20, 60);
        promptTextArea.setLineWrap(true);
        promptTextArea.setWrapStyleWord(true);
        promptTextArea.setToolTipText("Edit the prompt here");
        panel.add(new JScrollPane(promptTextArea));
    }

    private void addButtons(JPanel panel) {
        JPanel buttonPanel = new JPanel();
        JButton sendButton = new JButton("Send to Claude API");
        sendButton.addActionListener(e -> send());
        sendButton.setToolTipText("Send the prompt to the Claude API");
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> cancel());
        cancelButton.setToolTipText("Cancel and discard changes");
        buttonPanel.add(sendButton);
        buttonPanel.add(cancelButton);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    private void send() {
        finalPrompt = promptTextArea.getText();
        onComplete.run();
        dispose();
    }

    private void cancel() {
        finalPrompt = null;
        onComplete.run();
        dispose();
    }

    public String getFinalPrompt() {
        return finalPrompt;
    }

    /**
     * Displays the dialog and waits for user interaction.
     * If SKIP_PROMPT_CONFIRMATION is true, returns the prompt immediately.
     *
     * @param prompt the prompt text to review
     * @param title  the dialog title
     * @return the final prompt after user edits or null if cancelled
     */
    public static String showDialog(String prompt, String title) {
        if (DecyxConfig.SKIP_PROMPT_CONFIRMATION) {
            return prompt;
        }

        CountDownLatch latch = new CountDownLatch(1);
        PromptReviewDialog[] dialogHolder = new PromptReviewDialog[1];

        SwingUtilities.invokeLater(() -> {
            dialogHolder[0] = new PromptReviewDialog(prompt, title, latch::countDown);
        });

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return dialogHolder[0] != null ? dialogHolder[0].getFinalPrompt() : null;
    }
}
