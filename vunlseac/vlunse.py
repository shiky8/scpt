#!/bin/python_3.9

from typing import List,Dict,Union,Optional
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from PyQt5 import QtCore
import time, subprocess as sp
import os,ssl
class Vulnerability_Search():

    def __init__(self) -> None:
        ssl._create_default_https_context = ssl._create_unverified_context
        pass

    def vuln_search(self,bug:str, apiKey:str)->List[str]:
        url:str = 'https://vuldb.com/?api'  # url endpoint
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
        post_fields:Dict[str,str] = {'apikey': apiKey, 'search': bug}  # request
        request = Request(url, urlencode(post_fields).encode(), headers=header)
        jsone1:str = urlopen(request).read().decode()
        if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\vunlseac" not in dirk:
                    dirk  += "\\vunlseac"
                dirk = dirk.replace('\\vunlseac', '\\Reports\\Service_CVES\\')
        else:
            dirk: str = str(sp.getoutput('pwd'))
            if("/vunlseac" not in dirk):
                dirk+="/vunlseac"
            dirk = dirk.replace("/vunlseac", '/Reports/Service_CVES/')
        # print(dirk)
        with open(dirk+bug+"_vuldb.json", "w") as dop:
            dop.write(jsone1)
            dop.close()
        with open(dirk+bug+"_vuldb.json", 'r') as rop:
            D:List[str] = json.loads(rop.read())
            try:
                return D["result"]
            except:
                return D["response"]["status"]

class GUI(QtCore.QThread):

    Gui_Date_output = QtCore.pyqtSignal(object)

    def __init__(self,service: str,api_key: str) -> None:
        QtCore.QThread.__init__(self)
        self.service: str = service
        self.api_key: str=api_key

    def run(self) -> None:
        VS = Vulnerability_Search()
        bug: List[str] = VS.vuln_search(self.service, self.api_key)
        self.Gui_Date_output.emit('%s\n' % (str(bug)))
        time.sleep(1)
        QtCore.QCoreApplication.processEvents()

if __name__=="__main__":
    api_key:str="66a0565094d918c985d5de682c87606b"
    service:str="ssh 2"
    VS=Vulnerability_Search()
    bug:List[str]= VS.vuln_search(service, api_key)
    print(bug)
