# caller_selection_dialog.py

import threading
import javax.swing as swing
from javax.swing import JFrame, JPanel, JCheckBox, JButton, JScrollPane, BoxLayout, JLabel, JTextArea
from java.awt import BorderLayout, Dimension

from decyx.decompiler import decompile_function

# Dialog Class
class CallerSelectionDialog(JFrame):
    """
    Dialog for selecting which caller functions' code to include for additional context.
    """
    def __init__(self, callers, current_program, monitor, on_selection_complete):
        super(CallerSelectionDialog, self).__init__("Select Callers to Include")
        self.callers = callers
        self.current_program = current_program
        self.monitor = monitor
        self.on_selection_complete = on_selection_complete
        self.selected_callers = []
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel(BorderLayout())

            self.add_callers_panel(panel)
            self.add_preview_panel(panel)
            self.add_buttons_panel(panel)

            self.getContentPane().add(panel)
            self.setSize(800, 400)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print "Error initializing CallerSelectionDialog UI: {}".format(e)

    def add_callers_panel(self, panel):
        try:
            callers_panel = JPanel()
            callers_panel.setLayout(BoxLayout(callers_panel, BoxLayout.Y_AXIS))
            self.caller_checkboxes = []
            for caller in self.callers:
                checkbox = JCheckBox(caller.getName())
                checkbox.setSelected(False)
                checkbox.setToolTipText("Include code from caller: {}".format(caller.getName()))
                # Bind the caller and checkbox to the action listener using lambda with default arguments
                checkbox.addActionListener(lambda e, c=caller: self.update_preview(c, e))
                self.caller_checkboxes.append(checkbox)
                callers_panel.add(checkbox)

            scroll_callers = JScrollPane(callers_panel)
            scroll_callers.setPreferredSize(Dimension(200, 300))
            panel.add(scroll_callers, BorderLayout.WEST)
        except Exception as e:
            print "Error adding callers panel: {}".format(e)

    def update_preview(self, caller, event):
        try:
            if event.getSource().isSelected():
                decompiled_code, _ = decompile_function(caller, self.current_program, self.monitor)
                if decompiled_code:
                    code_length = len(decompiled_code)
                    self.update_preview_label(code_length)
                    self.set_preview_text(decompiled_code)
                else:
                    self.set_preview_text("Decompilation failed or no code available.")
                    self.update_preview_label(0)
            else:
                self.set_preview_text("Select a caller to see its decompiled code preview.")
                self.update_preview_label(0)
        except Exception as e:
            print "Error updating preview: {}".format(e)

    def add_preview_panel(self, panel):
        try:
            preview_panel = JPanel(BorderLayout())
            self.preview_label = JLabel("Caller Function Preview:")
            preview_panel.add(self.preview_label, BorderLayout.NORTH)

            self.preview_text_area = JTextArea()
            self.preview_text_area.setEditable(False)
            self.preview_text_area.setLineWrap(True)
            self.preview_text_area.setWrapStyleWord(True)
            self.preview_text_area.setText("Select a caller to see its decompiled code preview.")
            self.preview_text_area.setToolTipText("Decompiled code preview of the selected caller")
            self.preview_text_area.setCaretPosition(0)
            scroll_preview = JScrollPane(self.preview_text_area)
            preview_panel.add(scroll_preview, BorderLayout.CENTER)

            panel.add(preview_panel, BorderLayout.CENTER)
        except Exception as e:
            print "Error adding preview panel: {}".format(e)

    def add_buttons_panel(self, panel):
        try:
            buttons_panel = JPanel()
            buttons_panel.setLayout(BoxLayout(buttons_panel, BoxLayout.Y_AXIS))

            select_buttons = JPanel()
            select_all_button = JButton("Select All Callers")
            select_all_button.addActionListener(lambda e: self.select_all(True))
            select_all_button.setToolTipText("Select all caller checkboxes")
            unselect_all_button = JButton("Unselect All Callers")
            unselect_all_button.addActionListener(lambda e: self.select_all(False))
            unselect_all_button.setToolTipText("Unselect all caller checkboxes")
            select_buttons.add(select_all_button)
            select_buttons.add(unselect_all_button)

            action_buttons = JPanel()
            ok_button = JButton("OK")
            ok_button.addActionListener(lambda e: self.ok())
            ok_button.setToolTipText("Confirm selection and proceed")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel selection")
            action_buttons.add(ok_button)
            action_buttons.add(cancel_button)

            buttons_panel.add(select_buttons)
            buttons_panel.add(action_buttons)
            panel.add(buttons_panel, BorderLayout.SOUTH)
        except Exception as e:
            print "Error adding buttons panel: {}".format(e)

    def set_preview_text(self, text):
        try:
            self.preview_text_area.setText(text)
            self.preview_text_area.setCaretPosition(0)
        except Exception as e:
            print "Error setting preview text: {}".format(e) 

    def update_preview_label(self, length):
        try:
            self.preview_label.setText("Caller Function Preview (Length: {} characters):".format(length))
        except Exception as e:
            print "Error updating preview label: {}".format(e)

    def select_all(self, select):
        try:
            for checkbox in self.caller_checkboxes:
                checkbox.setSelected(select)
        except Exception as e:
            print "Error selecting all callers: {}".format(e)

    def ok(self):
        try:
            self.selected_callers = [
                caller for checkbox, caller in zip(self.caller_checkboxes, self.callers) 
                if checkbox.isSelected()
            ]
            self.on_selection_complete(self.selected_callers)
            self.dispose()
        except Exception as e:
            print "Error in OK action: {}".format(e)

    def cancel(self):
        try:
            self.selected_callers = []
            self.on_selection_complete(self.selected_callers)
            self.dispose()
        except Exception as e:
            print "Error in Cancel action: {}".format(e)

# Helper Functions
def show_caller_selection_dialog(callers, current_program, monitor):
    """
    Displays the CallerSelectionDialog and waits for user interaction.

    Args:
        callers (list): List of caller Function objects.
        current_program (Program): The current program context.
        monitor (TaskMonitor): The monitor object for progress tracking.

    Returns:
        list: The list of selected caller Function objects.
    """
    selected_callers = []
    dialog_complete = threading.Event()

    def on_selection(selected):
        selected_callers.extend(selected)
        dialog_complete.set()

    def create_dialog():
        CallerSelectionDialog(callers, current_program, monitor, on_selection)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_callers
