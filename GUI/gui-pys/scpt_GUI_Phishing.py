# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SCPT_gui_Phishing.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow_Ph(object):
    def setupUi(self, MainWindow_PHing):
        MainWindow_PHing.setObjectName("MainWindow")
        MainWindow_PHing.resize(800, 600)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("scpt.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow_PHing.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(MainWindow_PHing)
        self.centralwidget.setObjectName("centralwidget")
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setGeometry(QtCore.QRect(0, -10, 791, 551))
        self.frame.setStyleSheet("background-color: rgb(170, 0, 127);")
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.comboBox = QtWidgets.QComboBox(self.frame)
        self.comboBox.setGeometry(QtCore.QRect(70, 30, 201, 51))
        self.comboBox.setStyleSheet("background-color: rgb(0, 0, 127);")
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox_2 = QtWidgets.QComboBox(self.frame)
        self.comboBox_2.setGeometry(QtCore.QRect(90, 100, 241, 41))
        self.comboBox_2.setStyleSheet("background-color: rgb(0, 0, 0);")
        self.comboBox_2.setObjectName("comboBox_2")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(20, 40, 41, 18))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.frame)
        self.label_2.setGeometry(QtCore.QRect(20, 110, 58, 18))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.frame)
        self.label_3.setGeometry(QtCore.QRect(10, 180, 171, 41))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.frame)
        self.label_4.setGeometry(QtCore.QRect(20, 300, 58, 18))
        self.label_4.setObjectName("label_4")
        self.textEdit = QtWidgets.QTextEdit(self.frame)
        self.textEdit.setGeometry(QtCore.QRect(90, 260, 691, 271))
        self.textEdit.setStyleSheet("background-color: rgb(0, 0, 0);")
        self.textEdit.setObjectName("textEdit")
        self.pushButton = QtWidgets.QPushButton(self.frame)
        self.pushButton.setGeometry(QtCore.QRect(360, 100, 111, 41))
        self.pushButton.setStyleSheet("background-color: rgb(0, 0, 255);")
        self.pushButton.setObjectName("pushButton")
        self.lineEdit = QtWidgets.QLineEdit(self.frame)
        self.lineEdit.setGeometry(QtCore.QRect(180, 180, 321, 51))
        self.lineEdit.setStyleSheet("background-color: rgb(0, 0, 0);")
        self.lineEdit.setObjectName("lineEdit")
        MainWindow_PHing.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow_PHing)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 30))
        self.menubar.setObjectName("menubar")
        self.menuwindows = QtWidgets.QMenu(self.menubar)
        self.menuwindows.setObjectName("menuwindows")
        self.menupayload = QtWidgets.QMenu(self.menuwindows)
        self.menupayload.setObjectName("menupayload")
        self.menuhelp = QtWidgets.QMenu(self.menubar)
        self.menuhelp.setObjectName("menuhelp")
        MainWindow_PHing.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow_PHing)
        self.statusbar.setObjectName("statusbar")
        MainWindow_PHing.setStatusBar(self.statusbar)
        self.actionabout = QtWidgets.QAction(MainWindow_PHing)
        self.actionabout.setObjectName("actionabout")
        self.actionWEB = QtWidgets.QAction(MainWindow_PHing)
        self.actionWEB.setObjectName("actionWEB")
        self.actionMITM = QtWidgets.QAction(MainWindow_PHing)
        self.actionMITM.setObjectName("actionMITM")
        self.actioncryptography = QtWidgets.QAction(MainWindow_PHing)
        self.actioncryptography.setObjectName("actioncryptography")
        self.actiongenerate_payload = QtWidgets.QAction(MainWindow_PHing)
        self.actiongenerate_payload.setObjectName("actiongenerate_payload")
        self.actionreverseShell = QtWidgets.QAction(MainWindow_PHing)
        self.actionreverseShell.setObjectName("actionreverseShell")
        self.actionbotnet = QtWidgets.QAction(MainWindow_PHing)
        self.actionbotnet.setObjectName("actionbotnet")
        self.actionBrute_force = QtWidgets.QAction(MainWindow_PHing)
        self.actionBrute_force.setObjectName("actionBrute_force")
        self.actionbtc_exploit = QtWidgets.QAction(MainWindow_PHing)
        self.actionbtc_exploit.setObjectName("actionbtc_exploit")
        self.actiongoogle_drok = QtWidgets.QAction(MainWindow_PHing)
        self.actiongoogle_drok.setObjectName("actiongoogle_drok")
        self.actionport_scan = QtWidgets.QAction(MainWindow_PHing)
        self.actionport_scan.setObjectName("actionport_scan")
        self.actionVulnerability_scan = QtWidgets.QAction(MainWindow_PHing)
        self.actionVulnerability_scan.setObjectName("actionVulnerability_scan")
        self.menupayload.addAction(self.actiongenerate_payload)
        self.menupayload.addAction(self.actionreverseShell)
        self.menupayload.addAction(self.actionbotnet)
        self.menuwindows.addAction(self.actionWEB)
        self.menuwindows.addAction(self.actionMITM)
        self.menuwindows.addAction(self.actioncryptography)
        self.menuwindows.addAction(self.menupayload.menuAction())
        self.menuwindows.addAction(self.actionBrute_force)
        self.menuwindows.addAction(self.actionbtc_exploit)
        self.menuwindows.addAction(self.actiongoogle_drok)
        self.menuwindows.addAction(self.actionport_scan)
        self.menuwindows.addAction(self.actionVulnerability_scan)
        self.menuhelp.addAction(self.actionabout)
        self.menubar.addAction(self.menuwindows.menuAction())
        self.menubar.addAction(self.menuhelp.menuAction())

        self.retranslateUi(MainWindow_PHing)
        QtCore.QMetaObject.connectSlotsByName(MainWindow_PHing)

    def aboutss(self):
        from scpt_GUI_about import Ui_MainWindow_about
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_about()
        self.ui.setupUi(self.Form)
        # MainWindow_PHing.close()
        self.Form.show()

    def websss(self, MainWindow_PHing):
        from scpt_GUI_Web_scan import Ui_MainWindow_WS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_WS()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def mitmsss(self, MainWindow_PHing):
        from scpt_GUI_MITM import Ui_MainWindow_Mitm
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_Mitm()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def crptosss(self, MainWindow_PHing):
        from scpt_GUI_cryptography import Ui_MainWindow_crypto
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_crypto()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Payload_G(self, MainWindow_PHing):
        from scpt_GUI_generate_payload import Ui_MainWindow_GP
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_GP()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Payload_Rev(self, MainWindow_PHing):
        from scpt_GUI_Reverse_shell import Ui_MainWindow_RS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_RS()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Payload_bot(self, MainWindow_PHing):
        from scpt_GUI_botnet import Ui_MainWindow_botnet
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_botnet()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Brutessss(self, MainWindow_PHing):
        from scpt_GUI_brute_force import Ui_MainWindow_brute
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_brute()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()



    def BTC_esss(self, MainWindow_PHing):
        from scpt_GUI_btc_exploit import Ui_MainWindow_btc
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_btc()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Googlesss(self, MainWindow_PHing):
        from scpt_GUI_Google_Dork import Ui_MainWindow_GD
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_GD()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def Port_scansss(self, MainWindow_PHing):
        from scpt_GUI_Port_scan import Ui_MainWindow_PS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_PS()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def vunlssss(self, MainWindow_PHing):
        from scpt_GUI_vulnerability_search import Ui_MainWindow_VS
        # code the 2nd screen here
        self.Form = QtWidgets.QMainWindow()
        self.ui = Ui_MainWindow_VS()
        self.ui.setupUi(self.Form)
        MainWindow_PHing.close()
        self.Form.show()

    def retranslateUi(self, MainWindow_PHing):
        _translate = QtCore.QCoreApplication.translate
        MainWindow_PHing.setWindowTitle(_translate("MainWindow", "SCPT-Phishing"))
        self.comboBox.setItemText(0, _translate("MainWindow", "facebook"))
        self.comboBox.setItemText(1, _translate("MainWindow", "github"))
        self.comboBox.setItemText(2, _translate("MainWindow", "gmail"))
        self.comboBox.setItemText(3, _translate("MainWindow", "yahoo"))
        self.label.setText(_translate("MainWindow", "sites:"))
        self.label_2.setText(_translate("MainWindow", "options;"))
        self.label_3.setText(_translate("MainWindow", "send this url to the target:"))
        self.label_4.setText(_translate("MainWindow", "output:"))
        self.pushButton.setText(_translate("MainWindow", "run"))
        self.menuwindows.setTitle(_translate("MainWindow", "windows"))
        self.menupayload.setTitle(_translate("MainWindow", "payload"))
        self.menuhelp.setTitle(_translate("MainWindow", "help"))
        self.actionabout.setText(_translate("MainWindow", "about"))
        self.actionWEB.setText(_translate("MainWindow", "WEB"))
        self.actionMITM.setText(_translate("MainWindow", "MITM"))
        self.actioncryptography.setText(_translate("MainWindow", "cryptography"))
        self.actiongenerate_payload.setText(_translate("MainWindow", "generate-payload"))
        self.actionreverseShell.setText(_translate("MainWindow", "reverseShell"))
        self.actionbotnet.setText(_translate("MainWindow", "botnet"))
        self.actionBrute_force.setText(_translate("MainWindow", "Brute-force"))
        self.actionbtc_exploit.setText(_translate("MainWindow", "btc-exploit"))
        self.actiongoogle_drok.setText(_translate("MainWindow", "google-drok"))
        self.actionport_scan.setText(_translate("MainWindow", "port-scan"))
        self.actionVulnerability_scan.setText(_translate("MainWindow", "Vulnerability-scan"))

        self.actionWEB.triggered.connect(lambda:self.websss(MainWindow_PHing))
        self.actionMITM.triggered.connect(lambda:self.mitmsss(MainWindow_PHing))
        self.actioncryptography.triggered.connect(lambda:self.crptosss(MainWindow_PHing))
        self.actionBrute_force.triggered.connect(lambda:self.Brutessss(MainWindow_PHing))
        self.actiongenerate_payload.triggered.connect(lambda:self.Payload_G(MainWindow_PHing))
        self.actionreverseShell.triggered.connect(lambda:self.Payload_Rev(MainWindow_PHing))
        self.actionbotnet.triggered.connect(lambda:self.Payload_bot(MainWindow_PHing))
        self.actionbtc_exploit.triggered.connect(lambda:self.BTC_esss(MainWindow_PHing))
        self.actiongoogle_drok.triggered.connect(lambda:self.Googlesss(MainWindow_PHing))
        self.actionport_scan.triggered.connect(lambda:self.Port_scansss(MainWindow_PHing))
        self.actionVulnerability_scan.triggered.connect(lambda:self.vunlssss(MainWindow_PHing))
        self.actionabout.triggered.connect(self.aboutss)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow_PHing = QtWidgets.QMainWindow()
    ui = Ui_MainWindow_Ph()
    ui.setupUi(MainWindow_PHing)
    MainWindow_PHing.show()
    sys.exit(app.exec_())