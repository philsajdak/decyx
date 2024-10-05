# action_selection_dialog.py

import threading
import javax.swing as swing
from javax.swing import JFrame, JPanel, JCheckBox, JButton, BoxLayout, JLabel
from java.awt import BorderLayout

# Dialog Class
class ActionSelectionDialog(JFrame):
    """
    Dialog for selecting the actions to perform.
    """
    def __init__(self, on_selection_complete):
        super(ActionSelectionDialog, self).__init__("Select Actions to Perform")
        self.selected_actions = []
        self.on_selection_complete = on_selection_complete
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            self.add_instruction_label(panel)
            self.add_checkboxes(panel)
            self.add_buttons(panel)

            self.getContentPane().add(panel, BorderLayout.CENTER)
            self.setSize(300, 200)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print "Error initializing ActionSelectionDialog UI: {}".format(e)

    def add_instruction_label(self, panel):
        try:
            instruction_label = JLabel("Select the actions you want to perform:")
            instruction_label.setToolTipText("Choose the desired actions")
            panel.add(instruction_label)
        except Exception as e:
            print "Error adding instruction label: {}".format(e)

    def add_checkboxes(self, panel):
        try:
            self.rename_retype_checkbox = JCheckBox("Rename and Retype Variables")
            self.rename_retype_checkbox.setSelected(True)
            self.rename_retype_checkbox.setToolTipText("Rename variables and update their types")
            panel.add(self.rename_retype_checkbox)

            self.explanation_checkbox = JCheckBox("Get Function Explanation")
            self.explanation_checkbox.setSelected(False)
            self.explanation_checkbox.setToolTipText("Obtain explanations for functions")
            panel.add(self.explanation_checkbox)

            self.line_comments_checkbox = JCheckBox("Add Line Comments")
            self.line_comments_checkbox.setSelected(False)
            self.line_comments_checkbox.setToolTipText("Add comments to lines of code")
            panel.add(self.line_comments_checkbox)
        except Exception as e:
            print "Error adding checkboxes: {}".format(e)

    def add_buttons(self, panel):
        try:
            button_panel = JPanel()
            ok_button = JButton("OK")
            ok_button.addActionListener(lambda e: self.ok())
            ok_button.setToolTipText("Confirm action selection")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel action selection")
            button_panel.add(ok_button)
            button_panel.add(cancel_button)
            self.getContentPane().add(button_panel, BorderLayout.SOUTH)
        except Exception as e:
            print "Error adding buttons to ActionSelectionDialog: {}".format(e)

    def ok(self):
        try:
            self.selected_actions = []
            if self.rename_retype_checkbox.isSelected():
                self.selected_actions.append('rename_retype')
            if self.explanation_checkbox.isSelected():
                self.selected_actions.append('explanation')
            if self.line_comments_checkbox.isSelected():
                self.selected_actions.append('line_comments')
            self.on_selection_complete(self.selected_actions)
            self.dispose()
        except Exception as e:
            print "Error in OK action of ActionSelectionDialog: {}".format(e)

    def cancel(self):
        try:
            self.selected_actions = []
            self.on_selection_complete(self.selected_actions)
            self.dispose()
        except Exception as e:
            print "Error in Cancel action of ActionSelectionDialog: {}".format(e)

# Helper Functions
def show_action_select_dialog():
    """
    Displays the ActionSelectionDialog and waits for user interaction.

    Returns:
        list: The list of selected actions or an empty list if none selected.
    """
    selected_actions = []
    dialog_complete = threading.Event()

    def on_selection(selected):
        selected_actions.extend(selected)
        dialog_complete.set()

    def create_dialog():
        ActionSelectionDialog(on_selection)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_actions
