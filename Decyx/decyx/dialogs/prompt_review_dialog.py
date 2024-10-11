# prompt_review_dialog.py

import threading
import javax.swing as swing
from javax.swing import JFrame, JPanel, JButton, JScrollPane, BoxLayout, JLabel, JTextArea
from java.awt import BorderLayout

from decyx.config import SKIP_PROMPT_CONFIRMATION

# Dialog Class
class PromptReviewDialog(JFrame):
    """
    Dialog for reviewing and editing the prompt before sending it to the Claude API.
    """
    def __init__(self, prompt, title, on_submit, on_cancel):
        super(PromptReviewDialog, self).__init__(title)
        self.prompt = prompt
        self.on_submit = on_submit
        self.on_cancel = on_cancel
        self.final_prompt = None
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            self.add_instruction_label(panel)
            self.add_prompt_text_area(panel)
            self.add_buttons(panel)

            self.getContentPane().add(JScrollPane(panel), BorderLayout.CENTER)
            self.setSize(700, 500)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print "Error initializing PromptReviewDialog UI: {}".format(e)

    def add_instruction_label(self, panel):
        try:
            instruction_label = JLabel("Review and edit the final prompt before sending to Claude API:")
            instruction_label.setToolTipText("You can modify the prompt as needed")
            panel.add(instruction_label)
        except Exception as e:
            print "Error adding instruction label: {}".format(e)

    def add_prompt_text_area(self, panel):
        try:
            self.prompt_text_area = JTextArea(self.prompt, 20, 60)
            self.prompt_text_area.setLineWrap(True)
            self.prompt_text_area.setWrapStyleWord(True)
            self.prompt_text_area.setToolTipText("Edit the prompt here")
            panel.add(JScrollPane(self.prompt_text_area))
        except Exception as e:
            print "Error adding prompt text area: {}".format(e)

    def add_buttons(self, panel):
        try:
            button_panel = JPanel()
            send_button = JButton("Send to Claude API")
            send_button.addActionListener(lambda e: self.send())
            send_button.setToolTipText("Send the prompt to the Claude API")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel and discard changes")
            button_panel.add(send_button)
            button_panel.add(cancel_button)
            self.getContentPane().add(button_panel, BorderLayout.SOUTH)
        except Exception as e:
            print "Error adding buttons to PromptReviewDialog: {}".format(e)

    def send(self):
        try:
            self.final_prompt = self.prompt_text_area.getText()
            self.on_submit(self.final_prompt)
            self.dispose()
        except Exception as e:
            print "Error sending prompt: {}".format(e)

    def cancel(self):
        try:
            self.final_prompt = None
            self.on_cancel()
            self.dispose()
        except Exception as e:
            print "Error cancelling PromptReviewDialog: {}".format(e)

# Helper Functions
def show_prompt_review_dialog(prompt, title):
    """
    Displays the PromptReviewDialog and waits for user interaction.

    Args:
        prompt (str): The prompt text to review.
        title (str): The title of the dialog window.

    Returns:
        str or None: The final prompt after user edits or None if cancelled.
    """
    if SKIP_PROMPT_CONFIRMATION:
        return prompt

    final_prompt = []
    dialog_complete = threading.Event()

    def on_submit(final_p):
        final_prompt.append(final_p)
        dialog_complete.set()

    def on_cancel():
        final_prompt.append(None)
        dialog_complete.set()

    def create_dialog():
        PromptReviewDialog(prompt, title, on_submit, on_cancel)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return final_prompt[0]
