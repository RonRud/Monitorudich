import sys
from PyQt5.QtWidgets import QApplication, QWidget, QListWidget, QVBoxLayout, QListWidgetItem, QDialog, QTextEdit, \
    QLabel, QTableWidget, QHeaderView, QTableWidgetItem

from threading import Thread
import time
import re

class Logger_window(QWidget):
    def __init__(self, parent=None):
        super(Logger_window,self).__init__(parent)
        self.resize(1000,1000)

        self.setWindowTitle("Logger GUI")

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            self.logger_file_path = settings_file.readline().replace('\n','')

        self.table_logger = QTableWidget()
        self.table_logger.itemDoubleClicked.connect(self.open_more_options_dialog)
        self.table_logger.setColumnCount(2)
        self.table_logger.horizontalHeader().setStretchLastSection(True)
        self.table_logger.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)

        window_layout = QVBoxLayout(self)
        window_layout.addWidget(self.table_logger)
        self.setLayout(window_layout)

        self.logger_updater_thread = Thread(target=self.logger_list_updater)
        self.logger_updater_thread.start()



    def logger_list_updater(self):
        while (True):
            self.table_logger.clear()
            self.table_logger.clearContents()
            self.table_logger.setRowCount(0)
            with open(self.logger_file_path, "r") as logger_file:
                pattern = re.compile(
                    r"name: (?P<name>[a-zA-Z]*), address: (?P<address>0x[0-9a-zA-Z]*), eax: (?P<eax>0x[0-9a-zA-Z]*), ebx: (?P<ebx>0x[0-9a-zA-Z]*), ecx: (?P<ecx>0x[0-9a-zA-Z]*), edx: (?P<edx>0x[0-9a-zA-Z]*), (?P<param_bytes>params bytes: [0-9]*, )?presumed function bytes in hex: (?P<presumed_hex>[a-z0-9-]*), presumed function parameters: (?P<presumed_params>.*?),\n",
                    re.MULTILINE | re.DOTALL)
                matches = pattern.finditer(logger_file.read())
                for match in matches:
                    self.table_logger.insertRow(self.table_logger.rowCount())
                    tableWidgetNameItem = CustomQTableWidgetItem(match,match.group('name'))
                    self.table_logger.setItem(self.table_logger.rowCount()-1,0, tableWidgetNameItem)
                    tableWidgetPresumedItem = CustomQTableWidgetItem(match,match.group('presumed_params'))
                    self.table_logger.setItem(self.table_logger.rowCount()-1,1, tableWidgetPresumedItem)


                    #listWidgetItem = CustomQListWidgetItem(match, f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}")
                    #self.table_logger.addItem(listWidgetItem)

                    #QListWidgetItem(f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}", self.log_list)
                """logger_lines = logger_file.readlines()
                print("wha")
                print(logger_lines)
                for current_line in logger_lines:
                    current_line = current_line.replace('\n', '')
                    QListWidgetItem(current_line, self.log_list)
                """

            self.table_logger.setHorizontalHeaderLabels(("Name", "Presumed Capitalized Bullshit"))
            time.sleep(7) # crushes if there are constant reads

    def open_more_options_dialog(self, customQTableWidgetItem):
        self.dialog_instance = MoreInfoDialog(customQTableWidgetItem.regex_match)
        self.dialog_instance.show()

class CustomQTableWidgetItem(QTableWidgetItem):
    def __init__(self, regex_match, string):
        super(CustomQTableWidgetItem, self).__init__(string)
        self.regex_match = regex_match

class MoreInfoDialog(QWidget):
    """
    Dialog that shows more info about a function call
    """

    def __init__(self, regex_match, parent=None, ):
        super(MoreInfoDialog, self).__init__(parent)
        self.setWindowTitle("more info dialog")
        #self.parentWindow = window

        self.layout = QVBoxLayout(self)

        self.fullDocumantationString = QLabel("Wha")
        self.registersText = QLabel(f"Registers: eax:{regex_match.group('eax')}, ebx:{regex_match.group('ebx')}, ecx:{regex_match.group('ecx')}, edx:{regex_match.group('edx')}")
        self.hexStackText = QLabel(f"The presumed stack hex values are: {regex_match.group('presumed_hex')}")
        self.translatedStackText = QLabel(f"The presumed converted stack is: {regex_match.group('presumed_params')}")
        self.layout.addWidget(self.fullDocumantationString)
        self.layout.addWidget(self.registersText)
        self.layout.addWidget(self.hexStackText)
        self.layout.addWidget(self.translatedStackText)

class Table_view_logger_thingy_widget(QWidget):
    def __init__(self, parent=None):
        super(Table_view_logger_thingy_widget,self).__init__(parent)
        self.resize(1000,1000)

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            self.logger_file_path = settings_file.readline().replace('\n','')

        self.table_logger = QTableWidget()
        self.table_logger.itemDoubleClicked.connect(self.open_more_options_dialog)
        self.table_logger.setColumnCount(2)
        self.table_logger.horizontalHeader().setStretchLastSection(True)
        self.table_logger.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)

        window_layout = QVBoxLayout(self)
        window_layout.addWidget(self.table_logger)
        self.setLayout(window_layout)

        self.logger_updater_thread = Thread(target=self.logger_list_updater)
        self.logger_updater_thread.start()



    def logger_list_updater(self):
        while (True):
            self.table_logger.clear()
            self.table_logger.clearContents()
            self.table_logger.setRowCount(0)
            with open(self.logger_file_path, "r") as logger_file:
                pattern = re.compile(
                    r"name: (?P<name>[a-zA-Z]*), address: (?P<address>0x[0-9a-zA-Z]*), eax: (?P<eax>0x[0-9a-zA-Z]*), ebx: (?P<ebx>0x[0-9a-zA-Z]*), ecx: (?P<ecx>0x[0-9a-zA-Z]*), edx: (?P<edx>0x[0-9a-zA-Z]*), (?P<param_bytes>params bytes: [0-9]*, )?presumed function bytes in hex: (?P<presumed_hex>[a-z0-9-]*), presumed function parameters: (?P<presumed_params>.*?),\n",
                    re.MULTILINE | re.DOTALL)
                matches = pattern.finditer(logger_file.read())
                for match in matches:
                    self.table_logger.insertRow(self.table_logger.rowCount())
                    tableWidgetNameItem = CustomQTableWidgetItem(match,match.group('name'))
                    self.table_logger.setItem(self.table_logger.rowCount()-1,0, tableWidgetNameItem)
                    tableWidgetPresumedItem = CustomQTableWidgetItem(match,match.group('presumed_params'))
                    self.table_logger.setItem(self.table_logger.rowCount()-1,1, tableWidgetPresumedItem)


                    #listWidgetItem = CustomQListWidgetItem(match, f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}")
                    #self.table_logger.addItem(listWidgetItem)

                    #QListWidgetItem(f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}", self.log_list)
                """logger_lines = logger_file.readlines()
                print("wha")
                print(logger_lines)
                for current_line in logger_lines:
                    current_line = current_line.replace('\n', '')
                    QListWidgetItem(current_line, self.log_list)
                """

            self.table_logger.setHorizontalHeaderLabels(("Name", "Presumed Capitalized Bullshit"))
            time.sleep(7) # crushes if there are constant reads

    def open_more_options_dialog(self, customQTableWidgetItem):
        self.dialog_instance = MoreInfoDialog(customQTableWidgetItem.regex_match)
        self.dialog_instance.show()
