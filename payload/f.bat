echo #########user info > %temp%\winenumoutp22.txt
echo ##################Hostname >> %temp%\winenumoutp22.txt
hostname >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ##################whoami >> %temp%\winenumoutp22.txt
whoami >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ##################echo %%USERNAME%% >> %temp%\winenumoutp22.txt
echo %USERNAME% >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ##################net users >> %temp%\winenumoutp22.txt
net users >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ##################net user %%USERNAME%% >> %temp%\winenumoutp22.txt
net user %USERNAME% >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## systeminfo >> %temp%\winenumoutp22.txt
systeminfo >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## fsutil fsinfo drives >> %temp%\winenumoutp22.txt
fsutil fsinfo drives >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## path >> %temp%\winenumoutp22.txt
echo %PATH% >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## tasklist /SVC >> %temp%\winenumoutp22.txt
tasklist /SVC >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## Checking if .msi files are always installed with elevated privlidges>> %temp%\winenumoutp22.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\winenumoutp22.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo #### Checking for backup SAM files >> %temp%\winenumoutp22.txt

echo #### dir %SYSTEMROOT%epair\SAM >> %temp%\winenumoutp22.txt
dir %%SYSTEMROOT%%epair\SAM >> %temp%\winenumoutp22.txt

echo #### dir %SYSTEMROOT%\system32\configegback\SAM >> %temp%\winenumoutp22.txt
dir %%SYSTEMROOT%%\system32\configegback\SAM >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo #### USES AccessChk from sysinternals >> %temp%\winenumoutp22.txt
accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> %temp%\winenumoutp22.txt
accesschk.exe -uwcqv "Users" * /accepteula >> %temp%\winenumoutp22.txt
accesschk.exe -uwcqv "Everyone" * /accepteula >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## Checking for possible creds >> %temp%\winenumoutp22.txt

echo ################## type c:\sysprep.inf >> %temp%\winenumoutp22.txt
type c:\sysprep.inf >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## type c:\sysprep\sysprep.xml>> %temp%\winenumoutp22.txt
type c:\sysprep\sysprep.xml >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## Network Information >> %temp%\winenumoutp22.txt

echo ################## ipconfig /all >> %temp%\winenumoutp22.txt
ipconfig /all >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## net use (view current connetions) >> %temp%\winenumoutp22.txt
net use >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## net share (view shares) >> %temp%\winenumoutp22.txt
net share >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## arp -a >> %temp%\winenumoutp22.txt
arp -a >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## route print>> %temp%\winenumoutp22.txt
route print >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## netstat -nao >> %temp%\winenumoutp22.txt
netstat -nao >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## netsh firewall show state >> %temp%\winenumoutp22.txt
netsh firewall show state >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## netsh firewall show config >> %temp%\winenumoutp22.txt
netsh firewall show config >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## Shows wireless network information>> %temp%\winenumoutp22.txt
netsh wlan export profile key=clear
type wi-fi*.xml >> %temp%\winenumoutp22.txt
del wi-fi*.xml
echo. >> %temp%\winenumoutp22.txt


echo ################## schtasks /query /fo LIST /v >> %temp%\winenumoutp22.txt
schtasks /query /fo LIST /v >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## net start >> %temp%\winenumoutp22.txt
net start >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## DRIVERQUERY >> %temp%\winenumoutp22.txt
DRIVERQUERY >> %temp%\winenumoutp22.txt
echo. >> %temp%\winenumoutp22.txt

echo ################## Any mentions of "password" in the registry >> %temp%\winenumoutp22.txt

reg query HKLM /f password  /t REG_SZ  /s >> %temp%\winenumoutp22.txt

echo. >> %temp%\winenumoutp22.txt
echo ################## Checking for services >> %temp%\winenumoutp22.txt
wmic service get name,displayname,pathname,startmode | findstr /i "auto"  >> %temp%\winenumoutp22.txt
