#!/bin/python_3.9

from typing import List,Union,Optional,Dict,Set
import secrets
from eth_keys import keys
from PyQt5 import QtCore
import time,os
import subprocess as sp

class ETM_Brut():

    def __init__(self) -> None:
        pass

    def eth_brut(self,add2: str) -> Set[str]:
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

        while True:
            try:
                formats: int = secrets.randbits(256)
                private_key: str = "{:64x}".format(formats)
                private_key_bytes: bytes = bytes.fromhex(private_key)
                public_key: str = keys.PrivateKey(private_key_bytes).public_key
                public_key_byte: bytes = bytes.fromhex(str(public_key)[2:])
                address:str = keys.PublicKey(public_key_byte).to_address()
                if (str(address) == add2):
                    Eout: Set[str] = ("we found the private key= ", private_key, "  ,address= ", str(address))
                    with open(dirk + "_" + str(address) + "_eth.json", "a") as dop:
                        dop.write("we found the private key= "+ private_key+ "  ,address= "+str(address))
                        dop.write("\n")
                        dop.close()
                    return Eout
                else:
                    Eout: Set[str] = ("Wrong: " + "private key= ", private_key, "  ,address= ", str(address))
                    print(Eout)
                    w.write(Eout)
                    w.flush()
            except:
                pass



class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, adp: str) -> None:
            QtCore.QThread.__init__(self)
            self.adp = adp

        def run(self) -> None:
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
            while True:
                try:
                    formats: int = secrets.randbits(256)
                    private_key: str = "{:64x}".format(formats)
                    private_key_bytes: bytes = bytes.fromhex(private_key)
                    public_key: str = keys.PrivateKey(private_key_bytes).public_key
                    public_key_byte: bytes = bytes.fromhex(str(public_key)[2:])
                    address: str = keys.PublicKey(public_key_byte).to_address()
                    if (str(address) == self.adp):
                        Eout: Set[str] = ("we found the private key= ", private_key, "  ,address= ", str(address))
                        self.Gui_Date_output.emit('%s\n' % (str(Eout)))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        with open(dirk + "_" + str(address) + "_eth.json", "a") as dop:
                            dop.write("we found the private key= " + private_key + "  ,address= " + str(address))
                            dop.write("\n")
                            dop.close()
                        break
                    else:
                        Eout: Set[str] = ("Wrong: " + "private key= ", private_key, "  ,address= ", str(address))
                        self.Gui_Date_output.emit('%s\n' % (str(Eout)))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        print(Eout)
                        w.write(Eout)
                        w.flush()
                except:
                    pass




if __name__ == "__main__":

    add:str = "0xe48f4623a5a996ac22048f9fedefc8fa111cdb04"
    EH = ETM_Brut()
    Eoutput: Set[str] = EH.eth_brut(add)
    print(Eoutput)
    w = open('test_eth.txt', 'w')
    w.write("")
    w.close()


