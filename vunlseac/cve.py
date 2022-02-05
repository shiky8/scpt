#!/bin/python_3.9

from typing import List,Union,Optional,Dict
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
# import json
from PyQt5 import QtCore
import time,subprocess as sp
import os
import ssl
class CVE_Search():

    def __init__(self) -> None:
        ssl._create_default_https_context = ssl._create_unverified_context
        pass

    def cve_search(self,search:str) -> Dict[str,str]:
        url: str = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=' + search
        header: Dict[str,str]  = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
        req1 = Request(url, headers=header)
        req: str = urlopen(req1).read().decode()
        soup = BeautifulSoup(req, "html.parser")
        divs = soup.find('div', id='TableWithRules')
        a_tage = divs.find_all('td')
        cve_disc:str = ""
        all_cve: Dict[str,str]  = {}
        cve_url_Name: str = ""
        # cve_files = open(search.replace('+', '') + '_cve.txt', 'w')
        if "nt" in os.name:
                dirk: str = str(sp.getoutput('powershell pwd'))
                dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
                if "\\vunlseac" not in dirk:
                    dirk  += "\\vunlseac"
                dirk = dirk.replace('\\vunlseac', '\\Reports\\Service_CVES\\')
        else:
            dirk: str = str(sp.getoutput('pwd'))
            if ("/vunlseac" not in dirk):
                dirk += "/vunlseac"
            dirk = dirk.replace("/vunlseac",'/Reports/Service_CVES/')

        for div in a_tage:
            a = div.find('a', href=True)
            cve_url_Name += str(a)
            mi:str = str(div)
            if ('nowrap="nowrap"' in mi):
                continue
            else:
                cve_disc += mi
            cve_disc = cve_disc.replace('</td>', '').replace('<td valign="top">', 'Disc: ')
            cve_url_Name = cve_url_Name.replace('<a href="', 'URL: "https://cve.mitre.org').replace('>',' : Name: ').replace('</a>', '').replace('None', '').replace('</a', '')
            all_cve[cve_url_Name] = cve_disc
            with open(dirk+search+"_CVE.json", "a") as dop:
                dop.write(cve_url_Name)
                dop.write("\n")
                # dop.write(cve_disc)
                # json.dump(all_cve, dop)
                dop.close()
        # json.dump(all_cve, cve_files)
        return all_cve

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, search: str, dork: str) -> None:
            QtCore.QThread.__init__(self)
            self.search = search
            self.dork = dork

        def run(self) -> None:
            search: str = "ssh 2"
            CV=CVE_Search()
            d: Dict[str,str] = CV.cve_search(search.replace(' ', '+'))
            self.Gui_Date_output.emit('%s\n' % (str(d)))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()

if __name__=="__main__":
    # search: str = "5.10.0 kali7"
    search: str = "vsFTPd 2.3.4"
    CV = CVE_Search()
    d: Dict[str,str] = CV.cve_search(search.replace(' ', '+'))
    print(d)
