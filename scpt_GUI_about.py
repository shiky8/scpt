# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'scpt_gui_about.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow_about(object):
    def setupUi(self, MainWindow_about):
        MainWindow_about.setObjectName("MainWindow")
        MainWindow_about.resize(1283, 711)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("scpt.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow_about.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(MainWindow_about)
        self.centralwidget.setObjectName("centralwidget")
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setGeometry(QtCore.QRect(-10, 0, 1291, 731))
        self.frame.setStyleSheet("background-color: rgb(0, 0, 127);")
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(300, 0, 621, 51))
        self.label.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.frame)
        self.label_2.setGeometry(QtCore.QRect(0, 90, 1281, 101))
        self.label_2.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.frame)
        self.label_3.setGeometry(QtCore.QRect(10, 580, 541, 71))
        self.label_3.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.frame)
        self.label_4.setGeometry(QtCore.QRect(470, 530, 361, 41))
        self.label_4.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.frame)
        self.label_5.setGeometry(QtCore.QRect(630, 580, 651, 61))
        self.label_5.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.frame)
        self.label_6.setGeometry(QtCore.QRect(490, 230, 261, 81))
        self.label_6.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.frame)
        self.label_7.setGeometry(QtCore.QRect(0, 360, 901, 71))
        self.label_7.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_7.setObjectName("label_7")
        self.label_8 = QtWidgets.QLabel(self.frame)
        self.label_8.setGeometry(QtCore.QRect(540, 460, 121, 41))
        self.label_8.setStyleSheet("background-color: rgb(170, 0, 127);\n"
"font: 22pt \"Noto Sans\";")
        self.label_8.setObjectName("label_8")
        MainWindow_about.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow_about)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1283, 30))
        self.menubar.setObjectName("menubar")
        MainWindow_about.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow_about)
        self.statusbar.setObjectName("statusbar")
        MainWindow_about.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow_about)
        QtCore.QMetaObject.connectSlotsByName(MainWindow_about)

    def retranslateUi(self, MainWindow_about):
        _translate = QtCore.QCoreApplication.translate
        MainWindow_about.setWindowTitle(_translate("MainWindow", "SCPT-About"))
        self.label.setText(_translate("MainWindow", "    secure cross platform toolkit   (  SCPT    )"))
        self.label_2.setText(_translate("MainWindow", "   SCPT is a set of tools that help pentesters them work to done it faster and have fun  with it :)"))
        self.label_3.setText(_translate("MainWindow", "https://www.fb.com/SCPT-252710723284538"))
        self.label_4.setText(_translate("MainWindow", "https://github.com/shiky8"))
        self.label_5.setText(_translate("MainWindow", "https://www.instagram.com/mohamedshahat0/"))
        self.label_6.setText(_translate("MainWindow", "       version:1.0"))
        self.label_7.setText(_translate("MainWindow", "    made by Mohamed Shahat ( Shiky ) as AOU graduation project"))
        self.label_8.setText(_translate("MainWindow", "      :)"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow_about = QtWidgets.QMainWindow()
    ui = Ui_MainWindow_about()
    ui.setupUi(MainWindow_about)
    MainWindow_about.show()
    sys.exit(app.exec_())
