from urllib.request import Request, urlopen
from urllib.parse  import urlencode
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
# import subprocess as sp
from PyQt5 import QtCore
import time,subprocess as sp

class xss_scan():

    def __init__(self,cookie='security=low; PHPSESSID=077241fe9a6b4e56ce4c0dfc9b153c17'):
        # if
        self.my_cook=cookie
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
        soup = bs(req, "html.parser")  #
        return soup.find_all("form")

    def get_form_details(self,form):
        """
        This function extracts all possible useful information about an HTML `form`
        """
        details = {}
        # get the form action (target url)
        action = form.attrs.get("action").lower()
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        # print(details)
        return details

    def submit_form(self,form_details, url, value):
        """
        Submits a form given in `form_details`
        Params:
            form_details (list): a dictionary that contain form information
            url (str): the original URL that contain that form
            value (str): this will be replaced to all text and search inputs
        Returns the HTTP Response after form submission
        """
        # construct the full URL (if the url provided in action is relative)
        target_url = urljoin(url, form_details["action"])
        # get the inputs
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            # replace all text and search values with `value`
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                # if input name and value are not None,
                # then add them to the data of form submission
                data[input_name] = input_value

        if form_details["method"] == "post":
            post_data = urlencode(data).encode('ascii')
            req1 = Request(target_url)
            try:
                req1.add_header('Cookie', self.my_cook)
                post_response = urlopen(url=req1, data=post_data)
                return post_response.read().decode("utf-8")
            except:
                return "bad request"


        else:
            # GET request
            # print("get")
            query_string = urlencode(data)
            url2 = target_url + "?" + query_string
            req1 = Request(url2)
            req1.add_header('Cookie', self.my_cook)
            req = urlopen(req1)
            return req.read().decode("utf-8")

    def scan_xss(self,url):
        """
        Given a `url`, it prints all XSS vulnerable forms and
        returns True if any is vulnerable, False otherwise
        """
        # cookies =self.handle_auth(url)
        dirk: str = str(sp.getoutput('pwd'))
        if ("/web_scanner" not in dirk):
            dirk += "/web_scanner"
        dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
        # get all the forms from the URL
        forms = self.get_all_forms(url)
        # pprint(forms)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        # js_script = "<Script>alert('hi')</scripT>"
        js_script = open("xss-payload-list.txt", 'r')
        # returning value
        is_vulnerable = False
        # iterate over all forms
        for form in forms:
            form_details = self.get_form_details(form)
            # content = submit_form(form_details, url, js_script).content.decode()
            for payload in js_script:
                content = self.submit_form(form_details, url, payload)
                # print(content)
                if payload in content:
                    print(f"[+] XSS Detected on {url}")
                    print(f"[*] Form details:")
                    pprint(form_details)
                    is_vulnerable = True
                    with open(dirk + url.replace('http://','').replace('https://','').replace('/','')+ "_WEB_XSS.json", "a") as dop:
                        dop.write(f"[+] XSS Detected on {url}")
                        dop.write("\n")
                        dop.write(f"[*] Form details:")
                        dop.write("\n")
                        dop.write(str(form_details))
                        dop.write("\n")
                        dop.close()
                    # won't break because we want to print other available vulnerable forms
        return is_vulnerable

class GUI(QtCore.QThread):

        Gui_Date_output = QtCore.pyqtSignal(object)

        def __init__(self,url,cookio) -> None:
            QtCore.QThread.__init__(self)
            self.url = url
            self.cookieop = cookio


        def run(self) -> None:
            XSS = xss_scan(self.cookieop)
            """
                   Given a `url`, it prints all XSS vulnerable forms and
                   returns True if any is vulnerable, False otherwise
                   """
            # cookies =self.handle_auth(url)
            dirk: str = str(sp.getoutput('pwd'))
            if ("/web_scanner" not in dirk):
                dirk += "/web_scanner"
            dirk = dirk.replace('/web_scanner', '/Reports/WEB_bugs/')
            # get all the forms from the URL
            forms = XSS.get_all_forms(self.url)
            # pprint(forms)
            print(f"[+] Detected {len(forms)} forms on {self.url}.")
            self.Gui_Date_output.emit(str("[+] Detected"+ str(len(forms))+" forms on "+self.url))
            time.sleep(1)
            QtCore.QCoreApplication.processEvents()
            # js_script = "<Script>alert('hi')</scripT>"
            js_script = open("/home/shiky/PycharmProjects/scpt/web_scanner/xss-payload-list.txt", 'r')
            # returning value
            is_vulnerable = False
            # iterate over all forms
            for form in forms:
                form_details = XSS.get_form_details(form)
                # content = submit_form(form_details, url, js_script).content.decode()
                for payload in js_script:
                    content = XSS.submit_form(form_details, self.url, payload)
                    # print(content)
                    if payload in content:
                        print(f"[+] XSS Detected on {self.url}")
                        print(f"[*] Form details:")
                        pprint(form_details)
                        self.Gui_Date_output.emit(str("[+] XSS Detected on "+self.url))
                        self.Gui_Date_output.emit(str("[*] Form details:"))
                        self.Gui_Date_output.emit(str(form_details))
                        time.sleep(1)
                        QtCore.QCoreApplication.processEvents()
                        # is_vulnerable = True
                        with open(dirk + self.url.replace('http://', '').replace('https://', '').replace('/',
                                                                                                    '') + "_WEB_XSS.json",
                                  "a") as dop:
                            dop.write(f"[+] XSS Detected on {self.url}")
                            dop.write("\n")
                            dop.write(f"[*] Form details:")
                            dop.write("\n")
                            dop.write(str(form_details))
                            dop.write("\n")
                            dop.close()
                        # won't break because we want to print other available vulnerable forms

if __name__ == "__main__":
    # url = "https://xss-game.appspot.com/level1/frame"
    # url = "http://testphp.vulnweb.com/artists.php?artist=4"
    url ="http://192.168.82.128/dvwa/vulnerabilities/xss_r/"
    # url = "http://192.168.1.100/dvwa/vulnerabilities/xss_s/"
    # url = "http://192.168.1.100/dvwa/vulnerabilities/xss_r"
    # url = "http://192.168.1.100/mutillidae/index.php?page=dns-lookup.php"
    XSS = xss_scan()
    print("is_vulnerable:",XSS.scan_xss(url))