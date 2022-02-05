from urllib.request import Request, urlopen
from urllib.parse  import urlencode
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
# import subprocess as sp
from PyQt5 import QtCore
import time,subprocess as sp
from typing import Dict
class sql_injScan():
    def __init__(self,cookie='security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17'):
        self.my_cook = cookie
        print(self.my_cook)
        # pass

    def get_all_forms(self,url):
        """Given a `url`, it returns all forms from the HTML content"""
        header: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
        req1 = Request(url, headers=header)
        req1.add_header('Cookie', self.my_cook)
        req: str = urlopen(req1).read().decode()
        # soup = bs(req, "html.parser")  #
        soup = bs(req, "html.parser")  #
        return soup.find_all("form")

    def get_form_details(self,form):
        """
        This function extracts all possible useful information about an HTML `form`
        """
        details = {}
        # get the form action (target url)
        try:
            action = form.attrs.get("action").lower()
        except:
            action = None
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_vulnerable(self,response):
        """A simple boolean function that determines whether a page
        is SQL Injection vulnerable from its `response`"""
        errors = {
            # MySQL
            "you have an error in your sql syntax;",
            "warning: mysql",
            # SQL Server
            "unclosed quotation mark after the character string",
            # Oracle
            "quoted string not properly terminated",
        }
        for error in errors:
            # if you find one of these errors, return True
            if error in response.lower():  #
                return True
        # no error detected
        return False

    def scan_sql_injection(self,url):
        SQLPaykoads = open("SQL_INJ_Paylods.txt","r")
        dirk: str = str(sp.getoutput('pwd'))
        if ("/web_scanner" not in dirk):
            dirk += "/web_scanner"
        dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
        # test on URL
        subkk="&Submit=Submit#"
        for c in SQLPaykoads:
            # add quote/double quote character to the URL
            new_url = f"{url}{c}{subkk}".replace('\n','')
            print("[!] Trying", new_url)
            # make the HTTP request
            header: Dict[str, str] = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
            }
            req1 = Request(new_url, headers=header)
            req1.add_header('Cookie', self.my_cook)
            res: str = urlopen(req1).read().decode()
            # soup = bs(req, "html.parser")  #
            # res = s.get(new_url)#
            if self.is_vulnerable(res):
                # SQL Injection detected on the URL itself,
                # no need to preceed for extracting forms and submitting them
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                with open(dirk + url.replace('http://', '').replace('https://', '').replace('/', '') + "_WEB_SQL.json","a") as dop:
                    dop.write("[+] SQL Injection vulnerability detected, link: "+ new_url)
                    dop.write("\n")
                    dop.close()
                # return
        # test on HTML forms
        forms = self.get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        SQLPaykoads = open("SQL_INJ_Paylods.txt", "r")
        for form in forms:
            form_details = self.get_form_details(form)
            # print(SQLPaykoads.read())
            for c in SQLPaykoads:
                # print("hi")
                # print("s",c)
                # the data body we want to submit
                data = {}
                # print("hi0")
                for input_tag in form_details["inputs"]:
                    if input_tag["value"] or input_tag["type"] == "hidden":
                        # any input form that has some value or hidden,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        data[input_tag["name"]] = f"test{c}"
                # join the url with the action (form request URL)
                url = urljoin(url, form_details["action"])
                # print("hi")
                if form_details["method"] == "post":
                    post_data = urlencode(data).encode('ascii')
                    # req = urlopen(url2)
                    req1 = Request(url)
                    req1.add_header('Cookie', self.my_cook)
                    post_response = urlopen(url=req1, data=post_data)
                    res = post_response.read().decode("utf-8")
                    # print("hi1")
                    # res = s.post(url, data=data)#
                elif form_details["method"] == "get":
                    # print("hi2")
                    query_string = urlencode(data)
                    url2 = url + "?" + query_string
                    # print(data, target_url,query_string,url2)
                    req1 = Request(url2)
                    req1.add_header('Cookie', self.my_cook)
                    req = urlopen(req1)

                    # req = urlopen(url2)
                    res = req.read().decode("utf-8")
                    # res = s.get(url, params=data)#
                # test whether the resulting page is vulnerable
                if self.is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    print("Payload:",c)
                    with open(dirk + url.replace('http://', '').replace('https://', '').replace('/','') + "_WEB_SQL.json","a") as dop:
                        dop.write("[+] SQL Injection vulnerability detected, link:"+ url)
                        dop.write("\n")
                        dop.write(f"[*] Form details:")
                        dop.write("\n")
                        dop.write(str(form_details))
                        dop.write("\n")
                        dop.write("Payload: "+c+"\n")
                        dop.close()
                    break

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self, url,cookio) -> None:
            QtCore.QThread.__init__(self)
            self.url = url
            self.cookieop=cookio

        def run(self) -> None:
            SQL_INJ = sql_injScan(self.cookieop)
            SQLPaykoads = open("/home/shiky/PycharmProjects/scpt/web_scanner/SQL_INJ_Paylods.txt", "r")
            dirk: str = str(sp.getoutput('pwd'))
            if ("/web_scanner" not in dirk):
                dirk += "/web_scanner"
            dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
            # test on URL
            subkk = "&Submit=Submit#"
            for c in SQLPaykoads:
                # add quote/double quote character to the URL
                new_url = f"{self.url}{c}{subkk}".replace('\n', '')
                print("[!] Trying", new_url)
                self.Gui_Date_output.emit(str("[!] Trying "+ new_url))
                time.sleep(1)
                QtCore.QCoreApplication.processEvents()
                # make the HTTP request
                header: Dict[str, str] = {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
                }
                req1 = Request(new_url, headers=header)
                req1.add_header('Cookie', SQL_INJ.my_cook)
                res: str = urlopen(req1).read().decode()
                # soup = bs(req, "html.parser")  #
                # res = s.get(new_url)#
                if SQL_INJ.is_vulnerable(res):
                    # SQL Injection detected on the URL itself,
                    # no need to preceed for extracting forms and submitting them
                    print("[+] SQL Injection vulnerability detected, link:", new_url)
                    self.Gui_Date_output.emit(str("[+] SQL Injection vulnerability detected, link: "+ new_url))
                    time.sleep(1)
                    QtCore.QCoreApplication.processEvents()
                    with open(dirk + self.url.replace('http://', '').replace('https://', '').replace('/',
                                                                                                '') + "_WEB_SQL.json",
                              "a") as dop:
                        dop.write("[+] SQL Injection vulnerability detected, link: " + new_url)
                        dop.write("\n")
                        dop.close()
                    # return
            # test on HTML forms
            forms = SQL_INJ.get_all_forms(self.url)
            print(f"[+] Detected {len(forms)} forms on {self.url}.")
            self.Gui_Date_output.emit(str("[+] Detected "+ str(len(forms))+"forms on "+self.url))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()
            SQLPaykoads = open("/home/shiky/PycharmProjects/scpt/web_scanner/SQL_INJ_Paylods.txt", "r")
            for form in forms:
                form_details = SQL_INJ.get_form_details(form)
                # print(SQLPaykoads.read())
                for c in SQLPaykoads:
                    # print("hi")
                    # print("s",c)
                    # the data body we want to submit
                    data = {}
                    # print("hi0")
                    for input_tag in form_details["inputs"]:
                        if input_tag["value"] or input_tag["type"] == "hidden":
                            # any input form that has some value or hidden,
                            # just use it in the form body
                            try:
                                data[input_tag["name"]] = input_tag["value"] + c
                            except:
                                pass
                        elif input_tag["type"] != "submit":
                            # all others except submit, use some junk data with special character
                            data[input_tag["name"]] = f"test{c}"
                    # join the url with the action (form request URL)
                    self.url = urljoin(self.url, form_details["action"])
                    # print("hi")
                    if form_details["method"] == "post":
                        post_data = urlencode(data).encode('ascii')
                        # req = urlopen(url2)
                        req1 = Request(self.url)
                        req1.add_header('Cookie', SQL_INJ.my_cook)
                        post_response = urlopen(url=req1, data=post_data)
                        res = post_response.read().decode("utf-8")
                        # print("hi1")
                        # res = s.post(url, data=data)#
                    elif form_details["method"] == "get":
                        # print("hi2")
                        query_string = urlencode(data)
                        url2 = self.url + "?" + query_string
                        # print(data, target_url,query_string,url2)
                        req1 = Request(url2)
                        req1.add_header('Cookie', SQL_INJ.my_cook)
                        req = urlopen(req1)

                        # req = urlopen(url2)
                        res = req.read().decode("utf-8")
                        # res = s.get(url, params=data)#
                    # test whether the resulting page is vulnerable
                    if SQL_INJ.is_vulnerable(res):
                        print("[+] SQL Injection vulnerability detected, link:", self.url)
                        print("[+] Form:")
                        pprint(form_details)
                        print("Payload:", c)
                        self.Gui_Date_output.emit(str("[+] SQL Injection vulnerability detected, link: "+ self.url))
                        self.Gui_Date_output.emit(str("[+] Form:"))
                        self.Gui_Date_output.emit(str(form_details))
                        self.Gui_Date_output.emit(str("Payload: "+ c))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        with open(dirk + self.url.replace('http://', '').replace('https://', '').replace('/',
                                                                                                    '') + "_WEB_SQL.json",
                                  "a") as dop:
                            dop.write("[+] SQL Injection vulnerability detected, link:" + self.url)
                            dop.write("\n")
                            dop.write(f"[*] Form details:")
                            dop.write("\n")
                            dop.write(str(form_details))
                            dop.write("\n")
                            dop.write("Payload: " + c + "\n")
                            dop.close()
                        break

if __name__ == "__main__":
    # import sys
    # url = "http://testphp.vulnweb.com/artists.php?artist=1"
    # url ="http://testphp.vulnweb.com/artists.php?artist=1"
    url ="http://192.168.82.128/dvwa/vulnerabilities/sqli/?id=1"
    # url = "http://192.168.1.100/dvwa/vulnerabilities/sqli_blind/"
    # url = "https://www.youtube.com/watch?v=T1YtluXYwN8&list=RDMM&index=17&ab_channel=NiallStenson"
    SQL_INJ = sql_injScan()
    SQL_INJ.scan_sql_injection(url)