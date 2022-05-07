import sys
import time

from PyQt5.QtWidgets import (
    QApplication, QDialog, QMainWindow, QMessageBox, QFileDialog, QAction
)
import qdarkstyle
import datetime

from main_window import Ui_MainWindow
from logger_view_window import Logger_window
import os

class Window(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connectSignalsSlots()

        self.executableName = "Unknown_exe"

    def connectSignalsSlots(self):
        self.fileExplorerButton.clicked.connect(self.select_file_dialog_opener)
        self.launchByExeButton.clicked.connect(self.run_as_exe)
        self.saveButton.clicked.connect(self.save_log)
        self.loadButton.clicked.connect(self.load_from_log)

    def select_file_dialog_opener(self):
        self.executablePathTextEdit.setText(QFileDialog.getOpenFileName()[0])

    def run_as_exe(self):

        os.popen(f"cd .. && mainExecute.exe {self.executablePathTextEdit.toPlainText()}")
        os.popen(f"cd ../stringsModule && MalwareStringsSorter.exe {self.executablePathTextEdit.toPlainText()}")

        """ use for debugging
        process = os.popen(f"cd .. && mainExecute.exe {self.executablePathTextEdit.toPlainText()}")
        print(process.read())
        process.close()
        """
        time.sleep(2)  # allows strings to run
        self.executableName = self.executablePathTextEdit.toPlainText()[self.executablePathTextEdit.toPlainText().rfind('/')+1:]
        self.logger_view_window = Logger_window(self.executableName)
        self.logger_view_window.show()

    def save_log(self):

        os.chdir("..") #changes current working directory to the Monitorudich folder

        folder = "saved_logs"

        if not os.path.isdir(folder):
            os.mkdir(folder)

        save_directory_path = "saved_logs\\" + datetime.datetime.now().strftime("%d-%m-%Y,%H-%M-%S") + "," + self.executableName
        os.mkdir(save_directory_path)

        os.popen("copy logger_output.txt \"" + save_directory_path + "\"")
        os.popen("copy dllFunctionLogger.txt \"" + save_directory_path + "\"")
        os.popen("copy stringsModule\\filtered_strings.txt \"" + save_directory_path + "\"")
        os.popen("copy stringsModule\\selected_strings.txt \"" + save_directory_path + "\"")

        os.chdir("./GUI")  # returns the original cwd

    def load_from_log(self):
        os.chdir("..")  # changes current working directory to the Monitorudich folder

        save_directory_path = QFileDialog.getExistingDirectory()

        os.popen(f"copy /y \"{save_directory_path}\\logger_output.txt\" logger_output.txt")
        os.popen(f"copy /y \"{save_directory_path}\\dllFunctionLogger.txt\" dllFunctionLogger.txt")
        os.popen(f"copy /y \"{save_directory_path}\\filtered_strings.txt\" stringsModule\\filtered_strings.txt")
        os.popen(f"copy /y \"{save_directory_path}\\selected_strings.txt\" stringsModule\\selected_strings.txt")

        os.chdir("./GUI")  # returns the original cwd

        self.executableName = save_directory_path[save_directory_path.rfind(','):]
        self.logger_view_window = Logger_window(self.executableName)
        self.logger_view_window.show()

    def about(self):
        QMessageBox.about(
            self,
            "About Sample Editor",
            "<p>A sample text editor app built with:</p>"
            "<p>- PyQt</p>"
            "<p>- Qt Designer</p>"
            "<p>- Python</p>",
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyleSheet(qdarkstyle.load_stylesheet())

    win = Window()
    win.show()
    sys.exit(app.exec())