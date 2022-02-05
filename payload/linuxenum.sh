echo "user_name " >>/tmp/enum55.txt 
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
echo '' | sudo -S -l -k >>/tmp/enum55.txt
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
grep -i 'user\|group' /etc/apache2/envvars  >>/tmp/enum55.txt
echo "files enum " >>/tmp/enum55.txt 
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; >>/tmp/enum55.txt