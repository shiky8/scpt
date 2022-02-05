#!/bin/python_3.9

from typing import List,Union,Optional,Dict
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
from PyQt5 import QtCore
import time
import yaml,ssl

class GooGle_Dork():

    def __init__(self) -> None:
        ssl._create_default_https_context = ssl._create_unverified_context
        pass

    def dork(self,search:str) -> str:

        url: str = 'https://gtfobins.github.io/#' + search

        header:Dict[str,str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }

        RAW_URL = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/{}.md"
        newUrl =RAW_URL.format(search)
        req1 = Request(newUrl, headers=header)
        req: str = urlopen(req1).read().decode()
        data = list(yaml.load_all(req, Loader=yaml.SafeLoader))[0]
        # print(newUrl,data)
        return (newUrl,data)


class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, search: str, dork: str) -> None:
            QtCore.QThread.__init__(self)
            self.search = search
            # self.dork = dork

        def run(self) -> None:
            GD = GooGle_Dork()
            GD_Output = GD.dork(self.search)
            self.Gui_Date_output.emit('%s\n' % ( str(GD_Output)))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()

if __name__=="__main__":
    search:str = "nmap"
    # dork:int=3
    GD=GooGle_Dork()
    GD_Output:str = GD.dork(search)
    print(GD_Output)
