import sys
from PyQt5.QtWidgets import QApplication, QWidget, QListWidget, QVBoxLayout, QListWidgetItem, QDialog, QTextEdit, \
    QLabel, QTableWidget, QHeaderView, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem

from threading import Thread
import time
import re

active_alerts = []

class Logger_window(QWidget):
    def __init__(self, executable_name, parent=None):
        super(Logger_window,self).__init__(parent)
        self.resize(1000,1000)

        self.setWindowTitle("Logger GUI - " + executable_name)

        self.layout = QVBoxLayout(self)

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = Table_view_logger_thingy_widget()
        self.tab2 = PE_header_widget()
        self.tab3 = DLLs_and_functions_widget()
        self.tab4 = StringsWidget()
        self.tab5 = AlertsWidget()
        self.tabs.resize(300, 200)

        # Add tabs
        self.tabs.addTab(self.tab1, "Function logger")
        self.tabs.addTab(self.tab2, "PE header info")
        self.tabs.addTab(self.tab3, "View DLLs and functions")
        self.tabs.addTab(self.tab4, "Strings")
        self.tabs.addTab(self.tab5, "Alerts")

        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

class CustomQTableWidgetItem(QTableWidgetItem):
    def __init__(self, regex_match, documentation_string, string):
        super(CustomQTableWidgetItem, self).__init__(string)
        self.regex_match = regex_match
        self.documentation_string = documentation_string

class MoreInfoDialog(QWidget):
    """
    Dialog that shows more info about a function call
    """

    def __init__(self, regex_match, documentation_string, parent=None):
        super(MoreInfoDialog, self).__init__(parent)
        self.setWindowTitle("more info dialog")
        #self.parentWindow = window

        self.layout = QVBoxLayout(self)

        self.fullDocumantationString = QLabel(documentation_string)
        self.registersText = QLabel(f'<font color="green">Registers:</font><font color="yellow"> eax:</font><font color="white">{regex_match.group("eax")}</font><font color="yellow">, ebx:</font><font color="white">{regex_match.group("ebx")}</font><font color="yellow">, ecx:</font><font color="white">{regex_match.group("ecx")}</font><font color="yellow">, edx:</font><font color="white">{regex_match.group("edx")}</font>');        self.hexStackText = QLabel(f"<font color='green'>The presumed stack hex values are: </font><font color='white'>{regex_match.group('presumed_hex')}</font>")
        self.translatedStackText = QLabel(f"<font color='green'>The presumed converted stack is: </font><font color='white'>{regex_match.group('presumed_params')}</font>")
        self.layout.addWidget(self.fullDocumantationString)
        self.layout.addWidget(self.registersText)
        self.layout.addWidget(self.hexStackText)
        self.layout.addWidget(self.translatedStackText)



class Table_view_logger_thingy_widget(QWidget):
    def __init__(self, parent=None):
        super(Table_view_logger_thingy_widget,self).__init__(parent)
        self.resize(1000,1000)

        window_layout = QVBoxLayout(self)

        self.function_log_filter = QTextEdit()
        self.function_log_filter.setMaximumHeight(100)
        window_layout.addWidget(self.function_log_filter)

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            self.logger_file_path = settings_file.readline().replace('\n','')
            for i in range(6):
                self.fullDocumentationFilePath = settings_file.readline().replace('\n', '')  # get value from the seventh line

        self.table_logger = QTableWidget()
        self.table_logger.itemDoubleClicked.connect(self.open_more_options_dialog)
        self.table_logger.setColumnCount(2)
        self.table_logger.horizontalHeader().setStretchLastSection(True)
        self.table_logger.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)

        window_layout.addWidget(self.table_logger)
        self.setLayout(window_layout)

        self.documentation_dict_to_name = {}
        with open(self.fullDocumentationFilePath, "r") as full_documentation_file:
            pattern = re.compile(
                r"\n(?P<function_name>[a-zA-Z]+)-(?P<documentation>.*?\);)",
                re.MULTILINE | re.DOTALL)
            matches = pattern.finditer(full_documentation_file.read())
            for match in matches:
                self.documentation_dict_to_name[match.group('function_name')] = match.group('documentation')

        self.logger_updater_thread = Thread(target=self.logger_list_updater)
        self.logger_updater_thread.start()

    def logger_list_updater(self):
        alert_if_has_word = ["file","File","port","Port","thread","Thread","console","Console"]
        while (True):
            self.table_logger.clear()
            self.table_logger.clearContents()
            self.table_logger.setRowCount(0)
            with open(self.logger_file_path, "r+") as logger_file:
                pattern = re.compile(
                    r"name: (?P<name>[a-zA-Z]*), address: (?P<address>0x[0-9a-zA-Z]*), eax: (?P<eax>0x[0-9a-zA-Z]*), ebx: (?P<ebx>0x[0-9a-zA-Z]*), ecx: (?P<ecx>0x[0-9a-zA-Z]*), edx: (?P<edx>0x[0-9a-zA-Z]*), (?P<param_bytes>params bytes: [0-9]*, )?presumed function bytes in hex: (?P<presumed_hex>[a-z0-9-]*), presumed function parameters: (?P<presumed_params>.*?), alerted:(?P<already_alert>[a-z]*),\n",
                    re.MULTILINE | re.DOTALL)
                full_file_text = logger_file.read()
                matches = pattern.finditer(full_file_text)
                for match in matches:
                    if match.group('name') in self.documentation_dict_to_name:
                        if match.group('name').find(self.function_log_filter.toPlainText()) != -1 or self.function_log_filter.toPlainText() == "":
                            self.table_logger.insertRow(self.table_logger.rowCount())
                            tableWidgetNameItem = CustomQTableWidgetItem(match,self.documentation_dict_to_name[match.group('name')],match.group('name'))
                            self.table_logger.setItem(self.table_logger.rowCount()-1,0, tableWidgetNameItem)
                            tableWidgetPresumedItem = CustomQTableWidgetItem(match,self.documentation_dict_to_name[match.group('name')],match.group('presumed_params'))
                            self.table_logger.setItem(self.table_logger.rowCount()-1,1, tableWidgetPresumedItem)

                    if match.group('already_alert') == "false":
                        for filter_word in alert_if_has_word:
                            if match.group('name').find(filter_word) != -1:
                                alert_if_has_word.remove(filter_word)
                                active_alerts.append(f"Executable might have interacted with {filter_word}")
                                full_file_text = full_file_text[:match.span('already_alert')[0]] + "true " + full_file_text[match.span('already_alert')[1]:]
                        #listWidgetItem = CustomQListWidgetItem(match, f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}")
                    #self.table_logger.addItem(listWidgetItem)

                    #QListWidgetItem(f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}", self.log_list)
                logger_file.seek(0)
                logger_file.write(full_file_text)
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
        self.dialog_instance = MoreInfoDialog(customQTableWidgetItem.regex_match,customQTableWidgetItem.documentation_string)
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
            for i in range(9):
                self.dllFunctionLoggerPath = settings_file.readline().replace('\n','')

        with open(self.dllFunctionLoggerPath,"r") as dllFunctionLoggerFile:
            self.lines = dllFunctionLoggerFile.readlines()

        self.treeWidget = QTreeWidget()
        self.treeWidget.setColumnCount(3)
        self.treeWidget.setHeaderLabels(["Function Name", "Address", "Hook Status"])
        #self.treeWidget.setResizeMode(stretch)
        self.layout.addWidget(self.treeWidget)

        items = []

        waiting_for_add = False
        for current_line in self.lines:
            current_line = current_line.replace('\n','')
            if current_line[-1:] == ':': #new DLL
                self.item = QTreeWidgetItem([current_line])

                self.successfulItem = QTreeWidgetItem(["Hooked function successfully"])
                self.item.addChild(self.successfulItem)

                self.failedItem = QTreeWidgetItem(["Didn't Hook function"])
                self.item.addChild(self.failedItem)

                self.blacklistedItem = QTreeWidgetItem(["Blacklisted, not hooked"])
                self.item.addChild(self.blacklistedItem)

                items.append(self.item)
                """
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
            else:
                first_space = current_line.find(' ')
                second_space = current_line.find(' ',first_space+1)
                if current_line[second_space+1:] == "Hooked function successfully":
                    child = QTreeWidgetItem([current_line[:first_space], current_line[first_space+1:second_space], current_line[second_space+1:]])
                    self.successfulItem.addChild(child)
                elif current_line[second_space+1:] == "Didn't Hook function":
                    child = QTreeWidgetItem([current_line[:first_space], current_line[first_space+1:second_space], current_line[second_space+1:]])
                    self.failedItem.addChild(child)
                elif current_line[second_space+1:] == "Blacklisted, not hooked":
                    child = QTreeWidgetItem([current_line[:first_space], current_line[first_space+1:second_space], current_line[second_space+1:]])
                    self.blacklistedItem.addChild(child)

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
        self.treeWidget.addTopLevelItems(items)


        self.setLayout(self.layout)
        self.show()

class StringsWidget(QWidget):
    def __init__(self, parent=None):
        super(StringsWidget, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        selectedStringsLabel = QLabel("Selected Strings:")
        self.layout.addWidget(selectedStringsLabel)

        selectedStringsList = QListWidget()
        self.layout.addWidget(selectedStringsList)

        with open("C:\Windows\Temp\info_to_dll.txt","r") as settings_file:
            logger_file_path = settings_file.readline().replace('\n','')
            self.words_folder_file_path = logger_file_path[:logger_file_path.rfind('\\')]

        with open(self.words_folder_file_path + "\\StringsModule\\selected_strings.txt","r") as selectedStringsFile:
            lines = selectedStringsFile.readlines()
            for current_line in lines:
                selectedStringsList.addItem(QListWidgetItem(current_line))

        filteredStringsLabel = QLabel("Filtered Strings:")
        self.layout.addWidget(filteredStringsLabel)

        filteredStringsList = QListWidget()
        self.layout.addWidget(filteredStringsList)

        with open(self.words_folder_file_path + "\\StringsModule\\filtered_strings.txt","r") as selectedStringsFile:
            lines = selectedStringsFile.readlines()
            for current_line in lines:
                filteredStringsList.addItem(QListWidgetItem(current_line))

        self.setLayout(self.layout)
        self.show()


class AlertsWidget(QWidget):
    def __init__(self, parent=None):
        super(AlertsWidget, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        self.alertList = QListWidget()
        self.layout.addWidget(self.alertList)

        self.logger_updater_thread = Thread(target=self.showAlerts)
        self.logger_updater_thread.start()

        self.setLayout(self.layout)
        self.show()

    def showAlerts(self):

        while True:

            self.alertList.clear()

            for alert_str in active_alerts:
                self.alertList.addItem(QListWidgetItem(alert_str))
            time.sleep(4)