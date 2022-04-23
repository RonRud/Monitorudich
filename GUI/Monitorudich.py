import sys

from PyQt5.QtWidgets import (
    QApplication, QDialog, QMainWindow, QMessageBox, QFileDialog
)
import qdarkstyle


from main_window import Ui_MainWindow
from logger_view_window import Logger_window
import os

class Window(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connectSignalsSlots()

    def connectSignalsSlots(self):
        self.fileExplorerButton.clicked.connect(self.select_file_dialog_opener)
        self.launchByExeButton.clicked.connect(self.run_as_exe)

    def select_file_dialog_opener(self):
        self.executablePathTextEdit.setText(QFileDialog.getOpenFileName()[0])

    def run_as_exe(self):
        #print(self.executablePathTextEdit.toPlainText())
        #os.system()

        os.popen(f"cd .. && mainExecute.exe {self.executablePathTextEdit.toPlainText()}")
        """ use for debugging
        process = os.popen(f"cd .. && mainExecute.exe {self.executablePathTextEdit.toPlainText()}")
        print(process.read())
        process.close()
        """
        self.logger_view_window = Logger_window()
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