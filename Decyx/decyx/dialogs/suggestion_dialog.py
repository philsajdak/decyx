# suggestion_dialog.py

import threading
import javax.swing as swing
from javax.swing import (
    JFrame, JPanel, JCheckBox, JButton, JScrollPane, BoxLayout, JLabel,
    JTextField, JTextArea, JTable, DefaultCellEditor
)
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel
from java.awt import Color, Dimension, Font

from decompanion.utils import find_data_type_by_name, format_new_type
from decompanion.config import DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT

# Renderer Classes
class BoldRenderer(DefaultTableCellRenderer):
    """
    Custom renderer to display text in bold font.
    """
    def __init__(self):
        super(BoldRenderer, self).__init__()
        self.bold_font = None

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = super(BoldRenderer, self).getTableCellRendererComponent(
            table, value, is_selected, has_focus, row, column
        )
        if self.bold_font is None:
            font = component.getFont()
            self.bold_font = font.deriveFont(Font.BOLD)
        component.setFont(self.bold_font)
        return component

class NewTypeCellRenderer(DefaultTableCellRenderer):
    """
    Custom renderer to display new type cells in bold and color-coded based on validity.
    """
    def __init__(self, type_validity):
        super(NewTypeCellRenderer, self).__init__()
        self.bold_font = None
        self.type_validity = type_validity

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = super(NewTypeCellRenderer, self).getTableCellRendererComponent(
            table, value, is_selected, has_focus, row, column
        )
        if self.bold_font is None:
            font = component.getFont()
            self.bold_font = font.deriveFont(Font.BOLD)
        component.setFont(self.bold_font)
        if not self.type_validity[row]:
            component.setForeground(Color.RED)
        else:
            component.setForeground(table.getForeground())
        return component

class CheckboxRenderer(JCheckBox, swing.table.TableCellRenderer):
    """
    Custom renderer for checkbox cells in a table.
    """
    def __init__(self):
        super(CheckboxRenderer, self).__init__()
        self.setHorizontalAlignment(JLabel.CENTER)
        self.setOpaque(True)

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        if isinstance(value, bool):
            self.setSelected(value)
        elif isinstance(value, str):
            self.setSelected(value.lower() == 'true')
        else:
            self.setSelected(False)
        
        if is_selected:
            self.setForeground(table.getSelectionForeground())
            self.setBackground(table.getSelectionBackground())
        else:
            self.setForeground(table.getForeground())
            self.setBackground(table.getBackground())
        
        return self

# Dialog Classes
class SuggestionDialog(JFrame):
    """
    Dialog for displaying and applying suggestions from the Claude API.
    Handles both Apply and Cancel actions by invoking appropriate callbacks.
    """
    def __init__(self, suggestions, variables_with_old_types, tool, on_apply, on_cancel):
        super(SuggestionDialog, self).__init__("Claude Suggestions")
        self.suggestions = suggestions
        self.variables_with_old_types = variables_with_old_types
        self.tool = tool
        self.on_apply = on_apply
        self.on_cancel = on_cancel
        self.selected_suggestions = {
            'function_name': None,
            'variables': [{} for _ in self.suggestions['variables']],
            'explanation': None
        }
        self.type_validity = []
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            self.add_function_name_panel(panel)
            self.add_variable_table(panel)
            self.add_summary_label(panel)
            self.add_button_panel(panel)
            self.add_explanation_area(panel)
            self.add_apply_cancel_buttons(panel)

            self.getContentPane().add(panel)
            self.setSize(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print "Error initializing SuggestionDialog UI: {}".format(e)

    def add_function_name_panel(self, panel):
        func_panel = JPanel()
        func_panel.setLayout(BoxLayout(func_panel, BoxLayout.X_AXIS))
        self.func_checkbox = JCheckBox("Rename function to:")
        self.func_checkbox.setSelected(True)
        self.func_checkbox.setToolTipText("Check to rename the function")
        self.func_name_field = JTextField(self.suggestions.get('function_name', ""), 20)
        self.func_name_field.setMaximumSize(Dimension(200, 25))
        self.func_name_field.setToolTipText("Enter the new function name here")
        func_panel.add(self.func_checkbox)
        func_panel.add(self.func_name_field)
        panel.add(func_panel)

    def add_variable_table(self, panel):
        column_names = ["Old Name", "New Name", "Old Type", "New Type", "Rename", "Retype"]
        self.table_model = DefaultTableModel([], column_names)
        self.variable_table = JTable(self.table_model)
        self.populate_variable_table()
        self.set_table_column_widths()
        self.set_table_renderers()
        table_scroll = JScrollPane(self.variable_table)
        table_scroll.setPreferredSize(Dimension(700, 300))
        panel.add(table_scroll)

    def populate_variable_table(self):
        old_name_to_type = {var['old_name']: var['old_type'] for var in self.variables_with_old_types}
        for var in self.suggestions['variables']:
            old_name = var['old_name']
            new_name = var.get('new_name', "")
            old_type = old_name_to_type.get(old_name, 'unknown')
            new_type = format_new_type(var.get('new_type', ""))
            type_valid = find_data_type_by_name(new_type, self.tool) is not None
            self.type_validity.append(type_valid)
            self.table_model.addRow([old_name, new_name, old_type, new_type, True, type_valid])

    def set_table_column_widths(self):
        column_widths = [100, 100, 100, 100, 60, 60]
        for i, width in enumerate(column_widths):
            self.variable_table.getColumnModel().getColumn(i).setPreferredWidth(width)

    def set_table_renderers(self):
        try:
            bold_renderer = BoldRenderer()
            new_type_renderer = NewTypeCellRenderer(self.type_validity)
            checkbox_renderer = CheckboxRenderer()

            self.variable_table.getColumnModel().getColumn(1).setCellRenderer(bold_renderer)
            self.variable_table.getColumnModel().getColumn(3).setCellRenderer(new_type_renderer)
            checkbox_columns = [4, 5]
            for col in checkbox_columns:
                column = self.variable_table.getColumnModel().getColumn(col)
                column.setCellRenderer(checkbox_renderer)
                column.setCellEditor(DefaultCellEditor(JCheckBox()))
        except Exception as e:
            print "Error setting table renderers: {}".format(e)

    def add_summary_label(self, panel):
        try:
            total_vars = len(self.variables_with_old_types)
            num_suggested_renames = sum(
                var['old_name'] != var.get('new_name', var['old_name']) 
                for var in self.suggestions['variables']
            )
            num_suggested_retypes_valid = sum(1 for valid in self.type_validity if valid)
            num_suggested_retypes_invalid = len(self.type_validity) - num_suggested_retypes_valid

            summary_html = (
                "<html><b>Summary:</b><br>"
                "Rename suggestions: {1}/{0} total variables<br>"
                "Retype suggestions: {2}/{4} valid, {3}/{4} invalid</html>"
            ).format(total_vars, num_suggested_renames, num_suggested_retypes_valid, num_suggested_retypes_invalid, num_suggested_retypes_valid + num_suggested_retypes_invalid)

            summary_label = JLabel(summary_html)
            panel.add(summary_label)
        except Exception as e:
            print "Error adding summary label: {}".format(e)

    def add_button_panel(self, panel):
        try:
            button_panel = JPanel()
            buttons = [
                ("Select All Renames", lambda e: self.select_all(4, True)),
                ("Unselect All Renames", lambda e: self.select_all(4, False)),
                ("Select All Retypes", lambda e: self.select_all(5, True)),
                ("Unselect All Retypes", lambda e: self.select_all(5, False))
            ]
            for text, action in buttons:
                button = JButton(text)
                button.addActionListener(action)
                button.setToolTipText("{}".format(text))
                button_panel.add(button)
            panel.add(button_panel)
        except Exception as e:
            print "Error adding button panel: {}".format(e)

    def select_all(self, column, value):
        try:
            for row in range(self.table_model.getRowCount()):
                self.table_model.setValueAt(value, row, column)
        except Exception as e:
            print "Error selecting all in column {}: {}".format(column, e)

    def add_explanation_area(self, panel):
        try:
            if 'explanation' in self.suggestions and self.suggestions['explanation']:
                panel.add(JLabel("Explanation:"))
                self.explanation_area = JTextArea(self.suggestions['explanation'], 5, 30)
                self.explanation_area.setEditable(False)
                self.explanation_area.setLineWrap(True)
                self.explanation_area.setWrapStyleWord(True)
                self.explanation_area.setToolTipText("Explanation provided by the API")
                panel.add(JScrollPane(self.explanation_area))
        except Exception as e:
            print "Error adding explanation area: {}".format(e)

    def add_apply_cancel_buttons(self, panel):
        try:
            bottom_button_panel = JPanel()
            apply_button = JButton("Apply Selected")
            apply_button.addActionListener(lambda e: self.apply_changes())
            apply_button.setToolTipText("Apply the selected suggestions")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel without applying changes")
            bottom_button_panel.add(apply_button)
            bottom_button_panel.add(cancel_button)
            panel.add(bottom_button_panel)
        except Exception as e:
            print "Error adding apply and cancel buttons: {}".format(e)

    def apply_changes(self):
        try:
            self.process_function_name()
            self.process_variables()
            self.process_explanation()
            self.on_apply(self.selected_suggestions)
            self.dispose()
        except Exception as e:
            print "Error applying changes: {}".format(e)

    def process_function_name(self):
        if self.func_checkbox.isSelected():
            self.selected_suggestions['function_name'] = self.func_name_field.getText()
        else:
            self.selected_suggestions['function_name'] = None

    def process_variables(self):
        self.selected_suggestions['variables'] = []
        for row in range(self.table_model.getRowCount()):
            old_name = self.table_model.getValueAt(row, 0)
            new_name = self.table_model.getValueAt(row, 1)
            new_type = self.table_model.getValueAt(row, 3)
            rename = self.table_model.getValueAt(row, 4)
            retype = self.table_model.getValueAt(row, 5)

            var_suggestion = {'old_name': old_name}
            if rename:
                var_suggestion['new_name'] = new_name
            if retype:
                var_suggestion['new_type'] = new_type

            if rename or retype:
                self.selected_suggestions['variables'].append(var_suggestion)
            else:
                self.selected_suggestions['variables'].append(None)

    def process_explanation(self):
        if hasattr(self, 'explanation_area'):
            self.selected_suggestions['explanation'] = self.explanation_area.getText()
        else:
            self.selected_suggestions['explanation'] = None

    def cancel(self):
        try:
            self.on_cancel()
            self.dispose()
        except Exception as e:
            print "Error during cancel: {}".format(e)

# Helper Functions
def show_suggestion_dialog(suggestions, variables_with_old_types, tool):
    """
    Displays the SuggestionDialog and waits for user interaction.

    Args:
        suggestions (dict): Suggestions returned from the Claude API.
        variables_with_old_types (list): List of variables with their old types.
        tool (object): The Ghidra tool instance.

    Returns:
        dict or None: The selected suggestions or None if cancelled.
    """
    selected_suggestions = []
    dialog_complete = threading.Event()

    def on_apply(selected):
        selected_suggestions.append(selected)
        dialog_complete.set()

    def on_cancel():
        selected_suggestions.append(None)
        dialog_complete.set()

    def create_dialog():
        SuggestionDialog(suggestions, variables_with_old_types, tool, on_apply, on_cancel)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_suggestions[0]
