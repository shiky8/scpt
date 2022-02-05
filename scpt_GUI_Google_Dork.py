# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SCPT_gui_Google_Dork.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets

import google_dorking.google_dorl


class Ui_MainWindow_GD(object):
    item="site:*"
    def setupUi(self, MainWindow_GoD):
        MainWindow_GoD.setObjectName("MainWindow")
        MainWindow_GoD.resize(800, 655)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("scpt.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow_GoD.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(MainWindow_GoD)
        self.centralwidget.setObjectName("centralwidget")
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setGeometry(QtCore.QRect(0, 0, 801, 621))
        self.frame.setStyleSheet("background-color: rgb(226, 10, 255);")
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.comboBox = QtWidgets.QComboBox(self.frame)
        self.comboBox.setGeometry(QtCore.QRect(100, 80, 161, 41))
        self.comboBox.setStyleSheet("background-color: rgb(98, 25, 255);")
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.textEdit = QtWidgets.QTextEdit(self.frame)
        self.textEdit.setGeometry(QtCore.QRect(70, 260, 651, 281))
        self.textEdit.setObjectName("textEdit")
        self.textEdit.setStyleSheet("background-color: rgb(0, 0, 0);")
        self.label_2 = QtWidgets.QLabel(self.frame)
        self.label_2.setGeometry(QtCore.QRect(20, 300, 50, 18))
        self.label_2.setObjectName("label_2")
        self.pushButton = QtWidgets.QPushButton(self.frame)
        self.pushButton.setGeometry(QtCore.QRect(300, 183, 88, 41))
        self.pushButton.setStyleSheet("background-color: rgb(255, 57, 8);")
        self.pushButton.setObjectName("pushButton")
        self.lineEdit = QtWidgets.QLineEdit(self.frame)
        self.lineEdit.setGeometry(QtCore.QRect(70, 180, 221, 41))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.setStyleSheet("background-color: rgb(0, 0, 0);")
        self.label_3 = QtWidgets.QLabel(self.frame)
        self.label_3.setGeometry(QtCore.QRect(30, 90, 71, 18))
        self.label_3.setObjectName("label_3")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(20, 190, 50, 18))
        self.label.setObjectName("label")
        MainWindow_GoD.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow_GoD)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 30))
        self.menubar.setObjectName("menubar")
        self.menuwindows = QtWidgets.QMenu(self.menubar)
        self.menuwindows.setObjectName("menuwindows")
        self.menupayload = QtWidgets.QMenu(self.menuwindows)
        self.menupayload.setObjectName("menupayload")
        self.menuhelp = QtWidgets.QMenu(self.menubar)
        self.menuhelp.setObjectName("menuhelp")
        MainWindow_GoD.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow_GoD)
        self.statusbar.setObjectName("statusbar")
        MainWindow_GoD.setStatusBar(self.statusbar)
        self.actionabout = QtWidgets.QAction(MainWindow_GoD)
        self.actionabout.setObjectName("actionabout")
        self.actionweb = QtWidgets.QAction(MainWindow_GoD)
        self.actionweb.setObjectName("actionweb")
        self.actionMITM = QtWidgets.QAction(MainWindow_GoD)
        self.actionMITM.setObjectName("actionMITM")
        self.actioncryptography = QtWidgets.QAction(MainWindow_GoD)
        self.actioncryptography.setObjectName("actioncryptography")
        self.actionBrute_force = QtWidgets.QAction(MainWindow_GoD)
        self.actionBrute_force.setObjectName("actionBrute_force")
        self.actionPhishing = QtWidgets.QAction(MainWindow_GoD)
        self.actionPhishing.setObjectName("actionPhishing")
        self.actionbtc_exploit = QtWidgets.QAction(MainWindow_GoD)
        self.actionbtc_exploit.setObjectName("actionbtc_exploit")
        self.actionport_scan = QtWidgets.QAction(MainWindow_GoD)
        self.actionport_scan.setObjectName("actionport_scan")
        self.actionVulnerability_scan = QtWidgets.QAction(MainWindow_GoD)
        self.actionVulnerability_scan.setObjectName("actionVulnerability_scan")
        self.actiongenerate_payload = QtWidgets.QAction(MainWindow_GoD)
        self.actiongenerate_payload.setObjectName("actiongenerate_payload")
        self.actionbotnet = QtWidgets.QAction(MainWindow_GoD)
        self.actionbotnet.setObjectName("actionbotnet")
        self.actionreverseShell = QtWidgets.QAction(MainWindow_GoD)
        self.actionreverseShell.setObjectName("actionreverseShell")
        self.menupayload.addAction(self.actiongenerate_payload)
        self.menupayload.addAction(self.actionbotnet)
        self.menupayload.addAction(self.actionreverseShell)
        self.menuwindows.addAction(self.actionweb)
        self.menuwindows.addAction(self.actionMITM)
        self.menuwindows.addAction(self.actioncryptography)
        self.menuwindows.addAction(self.menupayload.menuAction())
        self.menuwindows.addAction(self.actionBrute_force)
        self.menuwindows.addAction(self.actionPhishing)
        self.menuwindows.addAction(self.actionbtc_exploit)
        self.menuwindows.addAction(self.actionport_scan)
        self.menuwindows.addAction(self.actionVulnerability_scan)
        self.menuhelp.addAction(self.actionabout)
        self.menubar.addAction(self.menuwindows.menuAction())
        self.menubar.addAction(self.menuhelp.menuAction())

        self.retranslateUi(MainWindow_GoD)
        QtCore.QMetaObject.connectSlotsByName(MainWindow_GoD)

    def aboutss(self):
        from scpt_GUI_about import Ui_MainWindow_about
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_about()
        self.ui.setupUi(self.Form)
        # MainWindow_GoD.close()
        self.Form.show()

    def websss(self, MainWindow_GoD):
        from scpt_GUI_Web_scan import Ui_MainWindow_WS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_WS()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def mitmsss(self, MainWindow_GoD):
        from scpt_GUI_MITM import Ui_MainWindow_Mitm
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_Mitm()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def crptosss(self, MainWindow_GoD):
        from scpt_GUI_cryptography import Ui_MainWindow_crypto
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_crypto()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def Payload_G(self, MainWindow_GoD):
        from scpt_GUI_generate_payload import Ui_MainWindow_GP
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_GP()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def Payload_Rev(self, MainWindow_GoD):
        from scpt_GUI_Reverse_shell import Ui_MainWindow_RS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_RS()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def Payload_bot(self, MainWindow_GoD):
        from scpt_GUI_botnet import Ui_MainWindow_botnet
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_botnet()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def Brutessss(self, MainWindow_GoD):
        from scpt_GUI_brute_force import Ui_MainWindow_brute
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_brute()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def Phisssss(self, MainWindow_GoD):
        from scpt_GUI_Phishing import Ui_MainWindow_Ph
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_Ph()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def BTC_esss(self, MainWindow_GoD):
        from scpt_GUI_btc_exploit import Ui_MainWindow_btc
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_btc()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()



    def Port_scansss(self, MainWindow_GoD):
        from scpt_GUI_Port_scan import Ui_MainWindow_PS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_PS()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def vunlssss(self, MainWindow_GoD):
        from scpt_GUI_vulnerability_search import Ui_MainWindow_VS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_VS()
        self.ui.setupUi(self.Form)
        MainWindow_GoD.close()
        self.Form.show()

    def handleItemPressed(self,index):
        self.item = self.comboBox.model().itemFromIndex(index)
        print("Do something with the selected item    = "+str(self.item.text()))
    def handleItemPressed2(self):
        try:
            print("Do something with the selected item2    = " + str(self.item.text()) + "\n" + str(self.lineEdit.text()))
            from google_dorking.google_dorl import GooGle_Dork
            GD = GooGle_Dork()
            GD_Output: str = GD.dork(str(self.lineEdit.text()), str(self.item.text()))
            print(GD_Output)
            self.textEdit.setText(GD_Output)
        except:
            print("Do something with the selected item2    = " + str(self.item) + "\n" + str(self.lineEdit.text()))
            from google_dorking.google_dorl import GooGle_Dork
            GD = GooGle_Dork()
            GD_Output: str = GD.dork(str(self.lineEdit.text()), str(self.item))
            print(GD_Output)
            self.textEdit.setText(GD_Output)


        

    def retranslateUi(self, MainWindow_GoD):
        _translate = QtCore.QCoreApplication.translate
        MainWindow_GoD.setWindowTitle(_translate("MainWindow", "SCPT-GoogleDork"))
        self.comboBox.setItemText(0, _translate("MainWindow", "site:*"))
        self.comboBox.setItemText(1, _translate("MainWindow", "intitle:\""))
        self.comboBox.setItemText(2, _translate("MainWindow", "inurl:"))
        self.comboBox.setItemText(3, _translate("MainWindow", "\""))
        self.comboBox.view().pressed.connect(self.handleItemPressed)
        self.label_2.setText(_translate("MainWindow", "output:"))
        self.pushButton.setText(_translate("MainWindow", "sub"))
        self.pushButton.clicked.connect(self.handleItemPressed2)
        self.label_3.setText(_translate("MainWindow", "dork_type:"))
        self.label.setText(_translate("MainWindow", "search:"))
        self.menuwindows.setTitle(_translate("MainWindow", "windows"))
        self.menupayload.setTitle(_translate("MainWindow", "payload"))
        self.menuhelp.setTitle(_translate("MainWindow", "help"))
        self.actionabout.setText(_translate("MainWindow", "about"))
        self.actionweb.setText(_translate("MainWindow", "web"))
        self.actionMITM.setText(_translate("MainWindow", "MITM"))
        self.actioncryptography.setText(_translate("MainWindow", "cryptography"))
        self.actionBrute_force.setText(_translate("MainWindow", "Brute-force"))
        self.actionPhishing.setText(_translate("MainWindow", "Phishing"))
        self.actionbtc_exploit.setText(_translate("MainWindow", "btc-exploit"))
        self.actionport_scan.setText(_translate("MainWindow", "port-scan"))
        self.actionVulnerability_scan.setText(_translate("MainWindow", "Vulnerability-scan"))
        self.actiongenerate_payload.setText(_translate("MainWindow", "generate-payload"))
        self.actionbotnet.setText(_translate("MainWindow", "botnet"))
        self.actionreverseShell.setText(_translate("MainWindow", "reverseShell"))

        self.actionweb.triggered.connect(lambda:self.websss(MainWindow_GoD))
        self.actionMITM.triggered.connect(lambda:self.mitmsss(MainWindow_GoD))
        self.actionBrute_force.triggered.connect(lambda:self.Brutessss(MainWindow_GoD))
        self.actionPhishing.triggered.connect(lambda:self.Phisssss(MainWindow_GoD))
        self.actiongenerate_payload.triggered.connect(lambda:self.Payload_G(MainWindow_GoD))
        self.actionbotnet.triggered.connect(lambda:self.Payload_bot(MainWindow_GoD))
        self.actionreverseShell.triggered.connect(lambda:self.Payload_Rev(MainWindow_GoD))
        self.actionbtc_exploit.triggered.connect(lambda:self.BTC_esss(MainWindow_GoD))
        self.actionport_scan.triggered.connect(lambda:self.Port_scansss(MainWindow_GoD))
        self.actionVulnerability_scan.triggered.connect(lambda:self.vunlssss(MainWindow_GoD))
        self.actionabout.triggered.connect(self.aboutss)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow_GoD = QtWidgets.QMainWindow()
    ui = Ui_MainWindow_GD()
    ui.setupUi(MainWindow_GoD)
    MainWindow_GoD.show()
    sys.exit(app.exec_())
