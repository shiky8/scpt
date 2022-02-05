# import requests
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import subprocess as sp
from PyQt5 import QtCore
import time,subprocess as sp

class sub_domloooop():
    def __init__(self):
        pass
    # function for scanning subdomains
    def domain_scanner(self,domain_name, sub_domnames):
        # loop for getting URL's
        for subdomain in sub_domnames:
            # making url by putting subdomain one by one
            url = f"https://{subdomain}.{domain_name}"
            dirk: str = str(sp.getoutput('pwd'))
            if ("/web_scanner" not in dirk):
                dirk += "/web_scanner"
            dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
            try:
                req1 = Request(url)
                response = urlopen(req1)
                print(f'[+] {url}', "states", response.getcode())
                with open(dirk + domain_name.replace('http://', '').replace('https://', '').replace('/','') + "_WEB_SubDIR.json","a") as dop:
                    dop.write("[+]" + url + "states" +  str(response.getcode()))
                    dop.write("\n")
                    dop.close()
            except HTTPError as e:
                print('The server couldn\'t fulfill the request.')
                print(f'[+] {url}', 'Error code: ', e.code)
            except URLError as e:
                print('We failed to reach a server.')
                print(f'[+] {url}', 'Reason: ', e.reason)

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self,domain_name, sub_domnames) -> None:
            QtCore.QThread.__init__(self)
            self.domain_name = domain_name
            self.sub_domnames = sub_domnames
            print(self.domain_name)

        def run(self) -> None:
            dirk: str = str(sp.getoutput('pwd'))
            if ("/web_scanner" not in dirk):
                dirk += "/web_scanner"
            dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
            # loop for getting URL's
            for subdomain in self.sub_domnames:
                # making url by putting subdomain one by one
                url = f"https://{subdomain}.{self.domain_name}"
                # dirk: str = str(sp.getoutput('pwd'))
                # dirk += '/Reports/WEB_bugs/'
                try:
                    req1 = Request(url)
                    response = urlopen(req1)
                    print(f'[+] {url}', "states", response.getcode())
                    self.Gui_Date_output.emit(str('[+] '+ url+', states: '+ str(response.getcode())))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    with open(dirk + self.domain_name.replace('http://', '').replace('https://', '').replace('/',
                                                                                                        '') + "_WEB_SubDIR.json",
                              "a") as dop:
                        dop.write("[+]" + url + "states" + str(response.getcode()))
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
                    self.Gui_Date_output.emit(str('[+] '+url +'Reason: '+ str(e.reason)))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
# main function



# def domain_scanner2(domain_name, sub_domnames):
#         # loop for getting URL's
#         for subdomain in sub_domnames:
#             # making url by putting subdomain one by one
#             url = f"https://{subdomain}.{domain_name}"
#             dirk: str = str(sp.getoutput('pwd'))
#             dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
#             try:
#                 req1 = Request(url)
#                 response = urlopen(req1)
#                 print(f'[+] {url}', "states", response.getcode())
#                 with open(dirk + domain_name.replace('http://', '').replace('https://', '').replace('/','') + "_WEB_SubDIR.json","a") as dop:
#                     dop.write("[+]" + url + "states" + str(response.getcode()))
#                     dop.write("\n")
#                     dop.close()
#             except HTTPError as e:
#                 print('The server couldn\'t fulfill the request.')
#                 print(f'[+] {url}', 'Error code: ', e.code)
#             except URLError as e:
#                 print('We failed to reach a server.')
#                 print(f'[+] {url}', 'Reason: ', e.reason)
if __name__ == '__main__':
    # inputting the domain name
    dom_name ="google.com"

    # openning the subdomain text file
    with open('subdomain.txt', 'r') as file:
        # reading the file
        name = file.read()

        # using spilitlines() function storing the list
        # of splitted strings
        sub_dom = name.splitlines()

    # calling the function for scanning the subdomains
    # and getting the url
    sopppp=sub_domloooop()
    sopppp.domain_scanner(dom_name,sub_dom)
    # domain_scanner2(dom_name,sub_dom)
    # soo=sub_dom()
    # soo.domain_scanner(dom_name,sub_dom)
    # soo.domain_scanner(dom_name, sub_dom)
