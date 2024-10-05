# model_selection_dialog.py

import threading
import javax.swing as swing
from javax.swing import JFrame, JPanel, JButton, JScrollPane, BoxLayout, JLabel, JComboBox
from java.awt import BorderLayout

class ModelSelectionDialog(JFrame):
    """
    Dialog for selecting the Claude model to use.
    """
    def __init__(self, models, default_index, on_selection_complete):
        super(ModelSelectionDialog, self).__init__("Select Claude Model")
        self.models = models
        self.selected_model = None
        self.default_index = default_index
        self.on_selection_complete = on_selection_complete
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            self.add_instruction_label(panel)
            self.add_model_combo_box(panel)
            self.add_buttons(panel)

            self.getContentPane().add(JScrollPane(panel), BorderLayout.CENTER)
            self.setSize(300, 150)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print("Error initializing ModelSelectionDialog UI: {}".format(e))

    def add_instruction_label(self, panel):
        try:
            instruction_label = JLabel("Select the Claude model to use:")
            instruction_label.setToolTipText("Choose the desired Claude model")
            panel.add(instruction_label)
        except Exception as e:
            print("Error adding instruction label: {}".format(e))

    def add_model_combo_box(self, panel):
        try:
            self.model_combo_box = JComboBox(self.models)
            self.model_combo_box.setSelectedIndex(self.default_index)
            self.model_combo_box.setToolTipText("Select a Claude model from the dropdown")
            panel.add(self.model_combo_box)
        except Exception as e:
            print("Error adding model combo box: {}".format(e))

    def add_buttons(self, panel):
        try:
            button_panel = JPanel()
            ok_button = JButton("OK")
            ok_button.addActionListener(lambda e: self.ok())
            ok_button.setToolTipText("Confirm model selection")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel model selection")
            button_panel.add(ok_button)
            button_panel.add(cancel_button)
            self.getContentPane().add(button_panel, BorderLayout.SOUTH)
        except Exception as e:
            print("Error adding buttons to ModelSelectionDialog: {}".format(e))

    def ok(self):
        try:
            self.selected_model = self.model_combo_box.getSelectedItem()
            self.on_selection_complete(self.selected_model)
            self.dispose()
        except Exception as e:
            print("Error in OK action of ModelSelectionDialog: {}".format(e))

    def cancel(self):
        try:
            self.selected_model = None
            self.on_selection_complete(self.selected_model)
            self.dispose()
        except Exception as e:
            print("Error in Cancel action of ModelSelectionDialog: {}".format(e))

def show_model_select_dialog(models):
    """
    Displays the ModelSelectionDialog and waits for user interaction.

    Args:
        models (list): List of available Claude models.

    Returns:
        str or None: The selected model or None if cancelled.
    """
    selected_model = []
    dialog_complete = threading.Event()

    def on_selection(selected):
        selected_model.append(selected)
        dialog_complete.set()

    def create_dialog():
        ModelSelectionDialog(models, 0, on_selection)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_model[0]
