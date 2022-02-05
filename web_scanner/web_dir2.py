# import requests
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import subprocess as sp
from PyQt5 import QtCore
import time,subprocess as sp
from typing import Dict
def dir_scanner(domain_name, dirs,cookie='security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17'):
    print('----URL after scanning subdomains----')

    # loop for getting URL's
    for dir in dirs:

        # making url by putting subdomain one by one
        url = f"https://{domain_name}/{dir}"
        dirk: str = str(sp.getoutput('pwd'))
        if ("/web_scanner" not in dirk):
            dirk += "/web_scanner"
        dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')

        # using try catch block to avoid crash of the
        # program
        try:
            header: Dict[str, str] = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
            }
            req1 = Request(url, headers=header)
            req1.add_header('Cookie', 'security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17')

            # req1 = Request(url)
            # req1.add_header('Cookie', cookie)
            response = urlopen(req1)
            print(f'[+] {url}', "states", response.getcode())
            with open(dirk + domain_name.replace('http://', '').replace('https://', '').replace('/', '') + "_WEB_DIR.json","a") as dop:
                dop.write("[+]"+ url+ "states"+ response.getcode())
                dop.write("\n")
                dop.close()
        except HTTPError as e:
            print('The server couldn\'t fulfill the request.')
            print(f'[+] {url}', 'Error code: ', e.code)
        except URLError as e:
            print('We failed to reach a server.')
            print(f'[+] {url}', 'Reason: ', e.reason)
        # try:

            # sending get request to the url
            # re=requests.get(url)

            # if after putting subdomain one by one url
            # is valid then printing the url
            # if(re.status_code==200):
            #     print(f'[+] {url}')
            # else:
            #     pass

            # if url is invalid then pass it
        # except requests.ConnectionError:
        #     pass

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, domain_name, dirs,cookie='security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17') -> None:
            QtCore.QThread.__init__(self)
            self.domain_name = domain_name
            self.dirs = dirs
            self.cookie=cookie
            print(self.domain_name)

        def run(self) -> None:
            dirk: str = str(sp.getoutput('pwd'))
            if ("/web_scanner" not in dirk):
                dirk += "/web_scanner"
            dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
            # loop for getting URL's
            for dir in dirs:

                # making url by putting subdomain one by one
                url = f"https://{self.domain_name}/{dir}"


                # using try catch block to avoid crash of the
                # program
                try:
                    header: Dict[str, str] = {
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
                    }
                    req1 = Request(url, headers=header)
                    req1.add_header('Cookie', 'security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17')

                    # req1 = Request(url)
                    # req1.add_header('Cookie', cookie)
                    response = urlopen(req1)
                    print(f'[+] {url}', "states", response.getcode())
                    self.Gui_Date_output.emit(str('[+] ' + url + ', states: ' + str(response.getcode())))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    with open(dirk + self.domain_name.replace('http://', '').replace('https://', '').replace('/',
                                                                                                        '') + "_WEB_DIR.json",
                              "a") as dop:
                        dop.write("[+]" + url + "states" + response.getcode())
                        dop.write("\n")
                        dop.close()
                except HTTPError as e:
                    print('The server couldn\'t fulfill the request.')
                    print(f'[+] {url}', 'Error code: ', e.code)
                    self.Gui_Date_output.emit('The server couldn\'t fulfill the request.')
                    self.Gui_Date_output.emit(str('[+] '+ url+ 'Error code: '+str(e.code)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                except URLError as e:
                    print('We failed to reach a server.')
                    print(f'[+] {url}', 'Reason: ', e.reason)
                    self.Gui_Date_output.emit('We failed to reach a server.')
                    self.Gui_Date_output.emit(str('[+] ' + url + 'Reason: ' + str(e.reason)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()


if __name__ == '__main__':
    # inputting the domain name
    # dom_name ="www.google.com"
    dom_name="http://192.168.82.128"

    # openning the subdomain text file
    # dirs_larg
    with open('dirs_small.txt', 'r') as file:
        # reading the file
        name = file.read()

        # using spilitlines() function storing the list
        # of splitted strings
        dirs = name.splitlines()

    # calling the function for scanning the subdomains
    # and getting the url
    dir_scanner(dom_name, dirs)