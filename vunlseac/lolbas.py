#!/bin/python_3.9

from typing import List, Union, Optional, Dict
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
from PyQt5 import QtCore
import time
import yaml


class GooGle_Dork():

    def __init__(self) -> None:
        pass

    def dork(self, search: str) -> str:
        url: str = 'https://lolbas-project.github.io/#' + search
        print(url)

        header: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }

        RAW_URL = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS-Project.github.io/master/_lolbas/"
        newUrl  = RAW_URL + search + '.md'
        print(newUrl)
        req1 = Request(newUrl, headers=header)
        req: str = urlopen(req1).read().decode()
        data = list(yaml.load_all(req, Loader=yaml.SafeLoader))[0]
        print(newUrl, data)

        # print(url)
        # req1 = Request(url, headers=header)
        # req:str = urlopen(req1).read().decode()
        # soup = BeautifulSoup(req, 'html.parser')
        #
        # tds = soup.find_all('a', class_='bin-name')
        # bins = [i.text for i in tds]
        # print(bins)
        # soup = BeautifulSoup(req, "lxml")
        # divs = soup.find('a', class_='bin-name')
        # a_tage = divs.find_all('a',class_="bin-name")
        # a_tage =  a_tage1.find("li")
        # print(divs)
        # data:str = ""
        # for div in a_tage:
        #     a = div.find('nmap', href=True)
        #     if a !=None:
        #         print( a)
        # data += a.attrs['href'] + "\n"
        # return data


class GUI(QtCore.QThread):
    Gui_Date_output = QtCore.pyqtSignal(object)

    def __init__(self, search: str, dork: str) -> None:
        QtCore.QThread.__init__(self)
        self.search = search
        # self.dork = dork

    def run(self) -> None:
        GD = GooGle_Dork()
        GD_Output = GD.dork(self.search)
        self.Gui_Date_output.emit('%s\n' % (str(GD_Output)))
        time.sleep(1)
        QtCore.QCoreApplication.processEvents()


if __name__ == "__main__":
    search: str = "AT.exe"
    # dork:int=3
    GD = GooGle_Dork()
    GD_Output: str = GD.dork(search)
    print(GD_Output)
