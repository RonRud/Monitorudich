import sys
from PyQt5.QtWidgets import QApplication, QWidget, QListWidget, QVBoxLayout, QListWidgetItem

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

        self.log_list = QListWidget()

        window_layout = QVBoxLayout(self)
        window_layout.addWidget(self.log_list)
        self.setLayout(window_layout)

        self.logger_updater_thread = Thread(target=self.logger_list_updater)
        self.logger_updater_thread.start()

    def logger_list_updater(self):
        while (True):
            self.log_list.clear()
            with open(self.logger_file_path, "r") as logger_file:
                pattern = re.compile(
                    r"name: (?P<name>[a-zA-Z]*), address: (?P<address>0x[0-9a-zA-Z]*), eax: (?P<eax>0x[0-9a-zA-Z]*), ebx: (?P<ebx>0x[0-9a-zA-Z]*), ecx: (?P<ecx>0x[0-9a-zA-Z]*), edx: (?P<edx>0x[0-9a-zA-Z]*), (?P<param_bytes>params bytes: [0-9]*, )?presumed function bytes in hex: (?P<presumed_hex>[a-z0-9-]*), presumed function parameters: (?P<presumed_params>.*?),\n",
                    re.MULTILINE | re.DOTALL)
                matches = pattern.finditer(logger_file.read())
                for match in matches:
                    QListWidgetItem(f"name: {match.group('name')}, presumed function parameters: {match.group('presumed_params')}", self.log_list)
                """logger_lines = logger_file.readlines()
                print("wha")
                print(logger_lines)
                for current_line in logger_lines:
                    current_line = current_line.replace('\n', '')
                    QListWidgetItem(current_line, self.log_list)
                """
            time.sleep(30) # crushes if there are constant reads

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Logger_window()

    window.show()
    sys.exit(app.exec_())