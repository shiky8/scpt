#!/bin/python_3.9

from typing import List,Union,Optional,Dict,Set
from bitcoin import  *
from PyQt5 import QtCore
import time,os
import subprocess as sp



class BTC_Brut():

    def __init__(self) -> None:
        pass
    def btc_wordlist_brut(self,add: str) -> Set[str]:
        Phrase = open('dictionary.txt', 'r')
        if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\brute\\last_brutfroce" not in dirk:
                    dirk  += "\\brute\\last_brutfroce"
                dirk = dirk.replace('\\brute\\last_brutfroce', '\\Reports\\brute-for\\')
        else:
                dirk: str = str(sp.getoutput('pwd'))
                if ("/brute/last_brutfroce" not in dirk):
                    dirk += "/brute/last_brutfroce"
                dirk = dirk.replace('/brute/last_brutfroce', '/Reports/brute-for/')
        for ph in Phrase:
            Private_Key: str = sha256(ph)
            Public_Key: str = privtopub(Private_Key)
            Adress: str = pubtoaddr(Public_Key)
            if str(Adress) == add:
                Bout : Set[str] = ("we found the: private-KEy= ", Private_Key, " ,address= ", Adress, " ,pub= ", Public_Key)
                with open(dirk + "_"+Adress + "_btc.json", "a") as dop:
                    dop.write("we found the: private-KEy= "+ Private_Key+ " ,address= "+ Adress+ " ,pub= "+ Public_Key)
                    dop.write("\n")
                    dop.close()
                return Bout
            else:
                Bout: Set[str] = (
                    "wrong key , private-KEy= " + Private_Key + " ,address= " + Adress + " ,pub= " + Public_Key + "\n")
                print(Bout)
               

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, adp: str) -> None:
            QtCore.QThread.__init__(self)
            self.adp = adp

        def run(self) -> None:
            Phrase = open('dictionary.txt', 'r')
            if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\brute\\last_brutfroce" not in dirk:
                    dirk  += "\\brute\\last_brutfroce"
                dirk = dirk.replace('\\brute\\last_brutfroce', '\\Reports\\brute-for\\')
            else:
                dirk: str = str(sp.getoutput('pwd'))
                if ("/brute/last_brutfroce" not in dirk):
                    dirk += "/brute/last_brutfroce"
                dirk = dirk.replace('/brute/last_brutfroce', '/Reports/brute-for/')

            for ph in Phrase:
                Private_Key: str = sha256(ph)
                Public_Key: str = privtopub(Private_Key)
                Adress: str = pubtoaddr(Public_Key)
                if str(Adress) == self.adp:
                    Bout: Set[str] = (
                    "we found the: private-KEy= ", Private_Key, " ,address= ", Adress, " ,pub= ", Public_Key)
                    self.Gui_Date_output.emit('%s\n' % (str(Bout)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    with open(dirk + "_" + Adress + "_btc.json", "a") as dop:
                        dop.write(
                            "we found the: private-KEy= " + Private_Key + " ,address= " + Adress + " ,pub= " + Public_Key)
                        dop.write("\n")
                        dop.close()
                    break
                else:
                    Bout: Set[str] = (
                            "wrong key , private-KEy= " + Private_Key + " ,address= " + Adress + " ,pub= " + Public_Key + "\n")
                    self.Gui_Date_output.emit('%s\n' % (str(Bout)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    print(Bout)





if __name__ == "__main__":
    # adp="1AxjE441yBmUcKCMG2tbHdKk1L1ZxxnsHq"
    adp: str = "15xjAzpf5zstEEQjg4AvyCQ4HYQEkgUmgc"
    # 1K5uTVRW8LUu91xL3f1d3C3VoUpNNBoHyV
    BTC=BTC_Brut()
    B_Output: Set[str] = BTC.btc_wordlist_brut(adp)
    print(B_Output)
    w = open('test.txt', 'w')
    w.write("")
    w.close()

# http://web.archive.org/web/20191129190724/https://2coin.org/privateKeyToAddress.html
# https://iancoleman.io/bitcoin-key-compression/
