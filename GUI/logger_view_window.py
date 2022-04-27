import sys
from PyQt5.QtWidgets import QApplication, QWidget, QListWidget, QVBoxLayout, QListWidgetItem, QDialog, QTextEdit, \
    QLabel, QTableWidget, QHeaderView, QTableWidgetItem, QTabWidget

from threading import Thread
import time
import re

class Logger_window(QWidget):
    def __init__(self, parent=None):
        super(Logger_window,self).__init__(parent)
        self.resize(1000,1000)

        self.setWindowTitle("Logger GUI")

        self.layout = QVBoxLayout(self)

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = Table_view_logger_thingy_widget()
        self.tab2 = PE_header_widget()
        self.tab3 = DLLs_and_functions_widget()
        self.tabs.resize(300, 200)

        # Add tabs
        self.tabs.addTab(self.tab1, "Function logger")
        self.tabs.addTab(self.tab2, "PE header info")
        self.tabs.addTab(self.tab3, "View DLLs and functions")

        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

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

class PE_header_widget(QWidget):
    def __init__(self, parent=None):
        super(PE_header_widget, self).__init__(parent)

        self.layout = QVBoxLayout(self)
        self.l = QTextEdit()

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            self.logger_file_path = settings_file.readline().replace('\n','')

        with open(self.logger_file_path, "r") as logger_file:
            logger_content = logger_file.read()
            self.l.setText(logger_content[:logger_content.find("End of PE header extraction\n")])

        self.layout.addWidget(self.l)
        self.setLayout(self.layout)

        self.show()

class DLLs_and_functions_widget(QWidget):
    def __init__(self, parent=None):
        super(DLLs_and_functions_widget, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            for i in range(8):
                self.dllFunctionLoggerPath = settings_file.readline().replace('\n','')


        with open(self.dllFunctionLoggerPath,"r") as dllFunctionLoggerFile:
            self.lines = dllFunctionLoggerFile.readlines()


        waiting_for_add = False
        for current_line in self.lines:
            current_line = current_line.replace('\n','')
            if current_line[-1:] == ':': #new DLL
                if waiting_for_add:
                    self.layout.addWidget(self.current_function_list_widget)
                    waiting_for_add = False
                label = QLabel(current_line)
                self.layout.addWidget(label)
                self.current_function_list_widget = QListWidget()
                waiting_for_add = True
            else:
                QListWidgetItem(current_line, self.current_function_list_widget)
        if waiting_for_add:
            self.layout.addWidget(self.current_function_list_widget)

        """
        self.dlls = [("kernel32.dll",["asdasdasdsad","asdsadsadjsndkasd","asdasbdjasbjndsajhdk"]),("wha.dll",["asdasdasdsad","asdsadsadjsndkasd","asdasbdjasbjndsajhdk"])]
    
        for dll in self.dlls:
            label = QLabel(dll[0])
            self.layout.addWidget(label)


            function_list_widget = QListWidget()
            for function_thing in dll[1]:
                QListWidgetItem(function_thing, function_list_widget)

            self.layout.addWidget(function_list_widget)
        """
        self.setLayout(self.layout)
        self.show()