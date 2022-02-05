from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from PyQt5 import QtCore
import time,subprocess as sp
from datetime import datetime
# from colorama import init, Fore
#
# # initialize colorama
# init()
#
# # define colors
# GREEN = Fore.GREEN
# RED   = Fore.RED
# RESET = Fore.RESET
class http_Sniff():
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

    def sniff_packets(self,process_packet,iface=None):
        """
        Sniff 80 port packets with `iface`, if None (default), then the
        scapy's default interface is used
        """
        if iface:
            # port 80 for http (generally)
            # `process_packet` is the callback
            sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
        else:
            # sniff with default interface
            sniff(filter="port 80", prn=process_packet, store=False)

    def process_packet(self,packet):
        """
        This function is executed whenever a packet is sniffed
        """
        if packet.haslayer(HTTPRequest):
            # if this packet is an HTTP Request
            # get the requested URL
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            # get the requester's IP Address
            ip = packet[IP].src
            # get the request method
            method = packet[HTTPRequest].Method.decode()
            dirk: str = str(sp.getoutput('pwd'))
            if ("/mitm" not in dirk):
                dirk += "/mitm"
            dirk = dirk.replace('/mitm', '/Reports/MITM_Rep/')
            date=str(datetime.today().strftime('%Y-%m-%d'))
            print(f"\n{self.GREEN}[+] {ip} Requested {url} with {method}{self.RESET}")
            if  packet.haslayer(Raw) and method == "POST":
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                print(f"\n{self.RED}[*] Some useful Raw data: {packet[Raw].load}{self.RESET}")
                with open(dirk +"_"+ date + "_MITM_Http.json", "a") as dop:
                    dop.write(str("\n[+] "+ip+" Requested "+url+" with "+method))
                    dop.write("\n")
                    dop.write(str("\n[*] Some useful Raw data:  " +str(packet[Raw].load)))
                    dop.write("\n")
                    dop.close()

class GUI(QtCore.QThread):
        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, iface) -> None:
            QtCore.QThread.__init__(self)
            self.iface = iface
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
        def process_packet(self, packet):
            """
            This function is executed whenever a packet is sniffed
            """
            if packet.haslayer(HTTPRequest):
                # if this packet is an HTTP Request
                # get the requested URL
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                # get the requester's IP Address
                ip = packet[IP].src
                # get the request method
                method = packet[HTTPRequest].Method.decode()
                dirk: str = str(sp.getoutput('pwd'))
                if ("/mitm" not in dirk):
                    dirk += "/mitm"
                dirk = dirk.replace('/mitm', '/Reports/MITM_Rep/')
                date = str(datetime.today().strftime('%Y-%m-%d'))
                print(f"\n{self.GREEN}[+] {ip} Requested {url} with {method}{self.RESET}")
                self.Gui_Date_output.emit((str("\n[+] "+ip+" Requested "+url+" with "+method)))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                if packet.haslayer(Raw) and method == "POST":
                    # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                    # then show raw
                    print(f"\n{self.RED}[*] Some useful Raw data: {packet[Raw].load}{self.RESET}")
                    self.Gui_Date_output.emit((str("\n[*] Some useful Raw data:  " + str(packet[Raw].load))))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    with open(dirk +"_"+ date + "_MITM_Http.json", "a") as dop:
                        dop.write(str("\n[+] " + ip + " Requested " + url + " with " + method))
                        dop.write("\n")
                        dop.write(str("\n[*] Some useful Raw data:  " + str(packet[Raw].load)))
                        dop.write("\n")
                        dop.close()
        def run(self) -> None:
            http_sn = http_Sniff()
            http_sn.sniff_packets(self.process_packet, self.iface)

if __name__ == "__main__":
    iface = str(input("Enter the iface: "))
    # show_raw = args.show_raw
    http_sn = http_Sniff()
    http_sn.sniff_packets(http_sn.process_packet,iface)
