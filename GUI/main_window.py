# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'qtGUIiMITTc.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(800, 232)
        self.actionopen_exe = QAction(MainWindow)
        self.actionopen_exe.setObjectName(u"actionopen_exe")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.gridLayoutWidget = QWidget(self.centralwidget)
        self.gridLayoutWidget.setObjectName(u"gridLayoutWidget")
        self.gridLayoutWidget.setGeometry(QRect(20, 0, 731, 179))
        self.gridLayout = QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        #self.textEdit = QTextEdit(self.gridLayoutWidget)
        #self.textEdit.setObjectName(u"textEdit")

        #self.gridLayout.addWidget(self.textEdit, 2, 1, 1, 1)

        #self.launchByPIDButton = QPushButton(self.gridLayoutWidget)
        #self.launchByPIDButton.setObjectName(u"launchByPIDButton")

        #self.gridLayout.addWidget(self.launchByPIDButton, 3, 1, 1, 1)


        self.saveButton = QPushButton("Save")
        self.gridLayout.addWidget(self.saveButton,2,1,1,1)

        self.loadButton = QPushButton("Load")
        self.gridLayout.addWidget(self.loadButton,2,2,1,1)


        self.executablePathTextEdit = QTextEdit(self.gridLayoutWidget)
        self.executablePathTextEdit.setObjectName(u"executablePathTextEdit")

        self.gridLayout.addWidget(self.executablePathTextEdit, 2, 0, 1, 1)

        self.launchByExeButton = QPushButton(self.gridLayoutWidget)
        self.launchByExeButton.setObjectName(u"launchByExeButton")

        self.gridLayout.addWidget(self.launchByExeButton, 3, 0, 1, 1)

        self.fileExplorerButton = QPushButton(self.gridLayoutWidget)
        self.fileExplorerButton.setObjectName(u"fileExplorerButton")

        self.gridLayout.addWidget(self.fileExplorerButton, 1, 0, 1, 1)

        self.gridLayout.setColumnStretch(0,3)
        self.gridLayout.setColumnStretch(1, 1)
        self.gridLayout.setColumnStretch(2, 1)
        #self.gridLayout.setRowStretch(0,3)
        #self.gridLayout.setRowStretch(1, 3)
        #self.gridLayout.setRowStretch(2, 3)


        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 800, 21))
        self.menubar.setContextMenuPolicy(Qt.ActionsContextMenu)
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.actionopen_exe.setText(QCoreApplication.translate("MainWindow", u"open exe", None))
        #self.textEdit.setHtml(QCoreApplication.translate("MainWindow", u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
#"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
#"p, li { white-space: pre-wrap; }\n"
#"</style></head><body style=\" font-family:'MS Shell Dlg 2'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
#"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Or enter PID of running program</p></body></html>", None))
        #self.launchByPIDButton.setText(QCoreApplication.translate("MainWindow", u"Link To Running process", None))
        self.executablePathTextEdit.setHtml(QCoreApplication.translate("MainWindow", u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:'MS Shell Dlg 2'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Enter executable full path (including .exe)</p></body></html>", None))
        self.launchByExeButton.setText(QCoreApplication.translate("MainWindow", u"Open Executable", None))
        self.fileExplorerButton.setText(QCoreApplication.translate("MainWindow", u"select file", None))
    # retranslateUi

