#!/bin/python_3.9

from typing import List,Union,Optional,Dict
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
from PyQt5 import QtCore
import time,ssl

class GooGle_Dork():

    def __init__(self) -> None:
        ssl._create_default_https_context = ssl._create_unverified_context
        pass

    def dork(self,search:str, type:Union[int,str]) -> str:
        self.dork: str = ''
        if type == 1 or type == "site:*":
            self.dork = 'site:*' + search + ''
        elif type == 2 or type == 'intitle:"':
            self.dork = 'intitle:"' + search + '"'
        elif type == 3 or type == 'inurl:':
            self.dork = 'inurl:' + search + ''
        else:
            self.dork = '"' + search + '"'
        url: str = 'https://www.google.com/search?q=' + self.dork

        header:Dict[str,str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
        req1 = Request(url, headers=header)
        req:str = urlopen(req1).read().decode()
        soup = BeautifulSoup(req, "html.parser")
        divs = soup.find('div', id='rso')
        a_tage = divs.find_all('div', class_='yuRUbf')
        data:str = ""
        for div in a_tage:
            a = div.find('a', href=True)
            data += a.attrs['href'] + "\n"
        return data

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, search: str, dork: str) -> None:
            QtCore.QThread.__init__(self)
            self.search = search
            self.dork = dork

        def run(self) -> None:
            GD = GooGle_Dork()
            GD_Output = GD.dork(self.search, self.dork)
            self.Gui_Date_output.emit('%s\n' % ( str(GD_Output)))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()

if __name__=="__main__":
    search:str = "CVE-2011-2523"
    dork:int=2
    GD=GooGle_Dork()
    GD_Output:str = GD.dork(search,dork)
    print(GD_Output)
