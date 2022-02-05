#!/bin/python_3.9

from typing import List,Union,Optional
import socket
from PyQt5 import QtCore
import time,subprocess as sp
from urllib.request import Request, urlopen
import os

class PORT_SCAN():

    def __init__(self,target:str)->None:
        self.target_p_ip:str = self.Get_ip(target)
        self.comm_ports = {"21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","53":"DNS","80":"HTTP","110":"POP3","143":"IMAP","25565":"Minecraft","3389":"Remote Desktop","5631":"PC Anywhere","1":"tcpmux","2":"compressnet","5":"rje","7":"echo"
                           ,"9":"discard","11":"systat","13":"daytime","17":"qotd","18":"msp","19":"chargen","20":"ftp-data","27":"nsw-fe","29":"msg-icp","31":"msg-auth","33":"dsp","37":"time","38":"rap","39":"rlp","41":"graphics"
                           ,"42":"name","111":"rpcbind","139":"netbios-ssn"
                           ,"445":"netbios-ssn","512":"exec","514":"login",
                           "514":"Shell","1099":"java-rmi","1524":"bindshell",
                           "2049":"nfs","2121":"FTP","3306":"mysql","5432":"postgresql",
                           "5900":"vnc","6000":"X11","6667":"irc","8009":"ajp13","8180":"HTTP","443":"ssl"}

    def Scan_All_Ports(self,timeoute:Optional[float]=0.5) -> str:
        out3:str = ""
        for port in range(1, 65535):
            tempss:str = self.scan_port(self.target_p_ip, port, timeoute)
            if tempss != None:
                out3 += tempss + "\n"
        return out3

    def Get_ip(self,ip:str) -> str:
        try:
            return socket.gethostbyname(ip)
        except:
            return "sorry"

    def Get_service_name(self,sock) ->bytes :
        # return sock.recv(1024)
        return sock.recv(2524)

    def scan_port(self,target_ipAdress:str, port:int,timeoute:Optional[float]=0.5)->Union[str,None]:
        try:
            Connects:socket.socket = socket.socket()
            Connects.settimeout(timeoute)
            Connects.connect((target_ipAdress, port))
            dirk: str =""
            # print("g06")
            if "nt" in os.name:
                # print("g0")
                dirk: str = str(sp.getoutput('powershell pwd'))
                # print("g")
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\port_scanner" not in dirk:
                    dirk  += "\\port_scanner"
                dirk = dirk.replace('\\port_scanner', '\\Reports\\open_ports\\')
                # print("g088")
               
            else:
                dirk: str = str(sp.getoutput('pwd'))
                if ("/port_scanner" not in dirk):
                    dirk += "/port_scanner"
                dirk = dirk.replace('/port_scanner', '/Reports/open_ports/')
            with open(dirk+target_ipAdress+"_AP.json", "a") as dop:
                try:
                    service: str = str(self.Get_service_name(Connects).decode())
                    outp: str = '[+] port ' + str(port) + ' is open' + " ,service: " + service
                    dop.write(outp)
                    dop.write("\n")
                    dop.close()
                    return outp
                except:
                    if port in [80,443,8009,8180]:
                        # print("ht")
                        try:

                            request = Request(target_ipAdress + ":" + str(port))
                            # req: str = urlopen(req1).read().decode()
                            # print("ht00")
                            # request = urllib2.Request(target_ipAdress+":"+str(port))
                            request.add_header('User-Agent',
                                               "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0")
                            # print("ht0")
                            response = urlopen(request)

                            try:
                                # print("ht2")
                                serverType = response.info().get('Server')
                                outp = '[+] port ' + str(port) + ' is open' + " ,service: " + serverType
                                dop.write(outp)
                                dop.write("\n")
                                dop.close()
                                return outp
                            except:
                                # print("error1")
                                pass
                        except:

                            request = Request("http://"+target_ipAdress + ":" + str(port))
                            # req: str = urlopen(req1).read().decode()
                            # print("ht00")
                            # request = urllib2.Request(target_ipAdress+":"+str(port))
                            request.add_header('User-Agent',
                                               "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0")
                            # print("ht0")
                            response = urlopen(request)

                            try:
                                # print("ht2")
                                serverType = response.info().get('Server')
                                outp = '[+] port ' + str(port) + ' is open' + " ,service: " + serverType
                                dop.write(outp)
                                dop.write("\n")
                                dop.close()
                                return outp
                            except:
                                # print("error2")
                                pass
                    try:
                        
                        # print("her0")
                        import socket as soc
                        outp = '[+] port ' + str(port) + ' is open' + " ,service: " + str(soc.getservbyport(port, 'tcp'))
                        # print("her")
                        dop.write(outp)
                        dop.write("\n")
                        dop.close()
                        return outp
                    except:
                        # print("error3")
                        pass


                    for k, v in self.comm_ports.items():
                        if (k in str(port)):
                            outp = '[+] port ' + str(port) + ' is open' + " ,service: " + v
                            dop.write(outp)
                            dop.write("\n")
                            dop.close()
                            return outp
                        else:
                            # print("error4")
                            pass
                    outp = '[+] port ' + str(port) + ' is open'
                    dop.write(outp)
                    dop.write("\n")
                    dop.close()
                    return outp
        except:
            # print("error5")
            pass

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self,targets:str,ports:str,option:str,timeoutes_str:Optional[float] = 0.5)->None:
            QtCore.QThread.__init__(self)
            self.target = targets
            self.ports = ports
            self.option = option
            self.timeoutes_str = timeoutes_str
            #

        def run(self)->None:
            if self.option == "2":
                port = self.ports
                if (',' in self.target):
                    sv: List[str] = self.target.split(',')
                    for i in sv:
                        print("target: " + str(i.strip(' ')))
                        self.Gui_Date_output.emit(str("target: " + str(i.strip(' '))))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        PS = PORT_SCAN(i.strip(' '))
                        if self.timeoutes_str == "":
                            if (',' in port):
                                PoS: List[str] = port.split(',')
                                for PK in PoS:
                                    Pi: int = int(PK.strip(' '))
                                    LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                                    if LPSOutput01 == None:
                                        pass
                                    else:
                                        print(LPSOutput01)
                                        self.Gui_Date_output.emit(str(LPSOutput01))
                                        time.sleep(1)
                                        QtCore.QCoreApplication.processEvents()
                            else:
                                Pi: int = int(port.strip(' '))
                                LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                                if LPSOutput01 == None:
                                    pass
                                else:
                                    print(LPSOutput01)
                                    self.Gui_Date_output.emit(str(LPSOutput01))
                                    time.sleep(1)
                                    QtCore.QCoreApplication.processEvents()


                        else:
                            if (',' in self.ports):
                                PoS: List[str] = self.ports.split(',')
                                for PK in PoS:
                                    Pi: int = int(PK.strip(' '))
                                    LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(self.timeoutes_str))
                                    if LPSOutput01 == None:
                                        pass
                                    else:
                                        print(LPSOutput01)
                                        self.Gui_Date_output.emit(str(LPSOutput01))
                                        time.sleep(1)
                                        QtCore.QCoreApplication.processEvents()
                            else:
                                Pi: int = int(self.ports.strip(' '))
                                LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(self.timeoutes_str))
                                if LPSOutput01 == None:
                                    pass
                                else:
                                    print(LPSOutput01)
                                    self.Gui_Date_output.emit(str(LPSOutput01))
                                    time.sleep(1)
                                    QtCore.QCoreApplication.processEvents()

                else:
                    PS = PORT_SCAN(self.target)
                    print("target: " + str(self.target))
                    self.Gui_Date_output.emit(str("target: " + str(self.target)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    if self.timeoutes_str == "":
                        if (',' in self.ports):
                            PoS: List[str] = self.ports.split(',')
                            for pk in PoS:
                                # print("here2")
                                Pi: int = int(pk.strip(' '))
                                PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                                if PSOutput02 == None:
                                    pass
                                else:
                                    print(PSOutput02)
                                    self.Gui_Date_output.emit(str(PSOutput02))
                                    time.sleep(1)
                                    QtCore.QCoreApplication.processEvents()
                        else:
                            Pi: int = int(self.ports.strip(' '))
                            PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                            if PSOutput02 == None:
                                pass
                            else:
                                print(PSOutput02)
                                self.Gui_Date_output.emit(str(PSOutput02))
                                time.sleep(1)
                                QtCore.QCoreApplication.processEvents()

                    else:
                        # print("here1")
                        if (',' in self.ports):
                            # print("here")
                            PoS: List[str] = self.ports.split(',')
                            for pk in PoS:
                                Pi: int = int(pk.strip(' '))
                                PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(self.timeoutes_str))
                                if PSOutput02 == None:
                                    pass
                                else:
                                    print(PSOutput02)
                                    self.Gui_Date_output.emit(str(PSOutput02))
                                    time.sleep(1)
                                    QtCore.QCoreApplication.processEvents()
                        else:
                            # print("here1")
                            Pi: int = int(self.ports.strip(' '))
                            PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(self.timeoutes_str))
                            if PSOutput02 == None:
                                pass
                            else:
                                print(PSOutput02)
                                self.Gui_Date_output.emit(str(PSOutput02))
                                time.sleep(1)
                                QtCore.QCoreApplication.processEvents()

            else:
                if (',' in self.target):
                    sv = self.target.split(',')
                    for i in sv:
                        print("target: " + str(i.strip(' ')))
                        self.Gui_Date_output.emit(str("target: " + str(i.strip(' '))))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        PS = PORT_SCAN(i.strip(' '))
                        if self.timeoutes_str == "":
                            LPSOutput01 = PS.Scan_All_Ports()
                            print(LPSOutput01)
                            self.Gui_Date_output.emit(str(LPSOutput01))
                            time.sleep(1)
                            QtCore.QCoreApplication.processEvents()
                        else:
                            LPSOutput01 = PS.Scan_All_Ports(float(self.timeoutes_str))
                            print(LPSOutput01)
                            self.Gui_Date_output.emit(str(LPSOutput01))
                            time.sleep(1)
                            QtCore.QCoreApplication.processEvents()
                else:
                    PS = PORT_SCAN(self.target)
                    print("target: " + str(self.target))
                    if self.timeoutes_str == "":
                        PSOutput02 = PS.Scan_All_Ports()
                        print(PSOutput02)
                        self.Gui_Date_output.emit(str(PSOutput02))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                    else:
                        PSOutput02 = PS.Scan_All_Ports(float(self.timeoutes_str))
                        print(PSOutput02)
                        self.Gui_Date_output.emit(str(PSOutput02))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()

if __name__=="__main__":
    target:str = str(input('enter terget sprate terget by ,: '))
    option=int(input('chose 1:for all ports , 2:for sepsefck port: '))
    timeoutes_str=str(input('chose, press enter to use the deflate timeout or set the timeout:  '))
    if option==2:
        port=str(input('enter the port sprate ports by , : '))
        if (',' in target):
            sv: List[str] = target.split(',')
            for i in sv:
                print("target: " + str(i.strip(' ')))
                PS = PORT_SCAN(i.strip(' '))
                if timeoutes_str=="":
                    if (',' in port):
                        PoS: List[str] = port.split(',')
                        for PK in PoS:
                            Pi: int = int(PK.strip(' '))
                            LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                            if LPSOutput01 == None:
                                pass
                            else:
                                print(LPSOutput01)
                    else:
                        Pi: int = int(port.strip(' '))
                        LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                        if LPSOutput01 == None:
                            pass
                        else:
                            print(LPSOutput01)


                else:
                    if (',' in port):
                        PoS: List[str] = port.split(',')
                        for PK in PoS:
                            Pi: int = int(PK.strip(' '))
                            LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                            if LPSOutput01 == None:
                                pass
                            else:
                                print(LPSOutput01)
                    else:
                        Pi: int = int(port.strip(' '))
                        LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                        if LPSOutput01 == None:
                            pass
                        else:
                            print(LPSOutput01)

        else:
            PS = PORT_SCAN(target)
            print("target: " + str(target))

            if timeoutes_str == "":
                if (',' in port):
                    PoS: List[str] = port.split(',')
                    for pk in PoS:
                        # print("here2")
                        Pi: int = int(pk.strip(' '))
                        PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                        if PSOutput02 == None:
                            pass
                        else:
                            print(PSOutput02)
                else:
                    Pi: int = int(port.strip(' '))
                    PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                    if PSOutput02 == None:
                        pass
                    else:
                        print(PSOutput02)

            else:
                # print("here1")
                if (',' in port):
                    # print("here")
                    PoS: List[str] = port.split(',')
                    for pk in PoS:
                        Pi: int = int(pk.strip(' '))
                        PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                        if PSOutput02 == None:
                            pass
                        else:
                            print(PSOutput02)
                else:
                    # print("here1")
                    Pi: int = int(port.strip(' '))
                    PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                    if PSOutput02 == None:
                        pass
                    else:
                        print(PSOutput02)

    else:
        if (',' in target):
            sv = target.split(',')
            for i in sv:
                print("target: " + str(i.strip(' ')))
                PS = PORT_SCAN(i.strip(' '))
                if timeoutes_str == "":
                    LPSOutput01 = PS.Scan_All_Ports()
                    print(LPSOutput01)
                else:
                    LPSOutput01 = PS.Scan_All_Ports(float(timeoutes_str))
                    print(LPSOutput01)
        else:
            PS = PORT_SCAN(target)
            print("target: " + str(target))
            if timeoutes_str == "":
                PSOutput02 = PS.Scan_All_Ports()
                print(PSOutput02)
            else:
                PSOutput02 = PS.Scan_All_Ports(float(timeoutes_str))
                print(PSOutput02)
