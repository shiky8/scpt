from setuptools import setup
import os
if "nt" in os.name:
        setup(
    name='scpt',
    version='1.0.0',
    packages=['.','Reports','templates','GUI', 'mitm', 'brute', 'brute.last_brutfroce', 'brute.protcal_brutfroce', 'colors', 'payload',
              'Phishing', 'vunlseac', 'hash_Name', 'raberDacky', 'btc_exploit', 'web_scanner', 'port_scanner',
              'google_dorking', 'hash_bruutefrocer', 'cryptography_me_she'],
    url='https://github.com/shiky8',
    license='MIT',
    author='mohamed shahat',
    author_email='mohamedshahat028@gmail.com',
    description='SCPT is a tool that help red team in them work',
    install_requires=['PyQt5==5.15.6','scapy==2.4.5','bitcoin==1.1.42','paramiko==2.8.0','pynput==1.7.4','Pillow==8.4.0','cryptography==35.0.0','beautifulsoup4==4.10.0','PyYAML==6.0','pycryptodome==3.11.0','pypiwin32==223'],
    entry_points={
        'console_scripts': [
            'scpt_cli=SCPT_cli_main:main',
            'scpt_gui=scpt_GUI_main:mainG',
            'scpt_web=SCPT_web_intf:mainW'
        ]
    },
    package_data={
        '':['*.png','*.txt','*.json'],
        'Reports':['brute-for/*.txt','brute-for/*.json','brute-for/*.png','brute-for/*.jpg','btc_exploit_Repo/*.txt','btc_exploit_Repo/*.json','btc_exploit_Repo/*.png','btc_exploit_Repo/*.jpg','MITM_Rep/*.txt','MITM_Rep/*.json','MITM_Rep/*.png','MITM_Rep/*.jpg','open_ports/*.txt','open_ports/*.json','open_ports/*.png','open_ports/*.jpg','phishing/*.txt','phishing/*.json','phishing/*.png','phishing/*.jpg','Service_CVES/*.txt','Service_CVES/*.json','Service_CVES/*.png','Service_CVES/*.jpg','shell_repo/*.txt','shell_repo/*.json','shell_repo/*.png','shell_repo/*.jpg','WEB_bugs/*.txt','WEB_bugs/*.json','WEB_bugs/*.png','WEB_bugs/*.jpg'],
        'templates':['*.html','assets/css/*.css','assets/js/*.js','assets/bootstrap/css/*.css','assets/img/*.png','assets/img/about/*.png','assets/img/portfolio/*.jpg','assets/img/team/*.jpg']
    })
else:
    setup(
    name='scpt',
    version='1.0.0',
    packages=['.','Reports','templates','GUI', 'mitm', 'brute', 'brute.last_brutfroce', 'brute.protcal_brutfroce', 'colors', 'payload',
              'Phishing', 'vunlseac', 'hash_Name', 'raberDacky', 'btc_exploit', 'web_scanner', 'port_scanner',
              'google_dorking', 'hash_bruutefrocer', 'cryptography_me_she'],
    url='https://github.com/shiky8',
    license='MIT',
    author='mohamed shahat',
    author_email='mohamedshahat028@gmail.com',
    description='SCPT is a tool that help red team in them work',
    install_requires=['PyQt5==5.15.6','scapy==2.4.5','bitcoin==1.1.42','paramiko==2.8.0','pynput==1.7.4','Pillow==8.4.0','cryptography==35.0.0','beautifulsoup4==4.10.0','PyYAML==6.0','pycryptodome==3.11.0'],
    entry_points={
        'console_scripts': [
            'scpt_cli=SCPT_cli_main:main',
            'scpt_gui=scpt_GUI_main:mainG',
            'scpt_web=SCPT_web_intf:mainW'
        ]
    },
    package_data={
	'':['*.png','*.txt','*.json'],
	'Reports':['brute-for/*.txt','brute-for/*.json','brute-for/*.png','brute-for/*.jpg','btc_exploit_Repo/*.txt','btc_exploit_Repo/*.json','btc_exploit_Repo/*.png','btc_exploit_Repo/*.jpg','MITM_Rep/*.txt','MITM_Rep/*.json','MITM_Rep/*.png','MITM_Rep/*.jpg','open_ports/*.txt','open_ports/*.json','open_ports/*.png','open_ports/*.jpg','phishing/*.txt','phishing/*.json','phishing/*.png','phishing/*.jpg','Service_CVES/*.txt','Service_CVES/*.json','Service_CVES/*.png','Service_CVES/*.jpg','shell_repo/*.txt','shell_repo/*.json','shell_repo/*.png','shell_repo/*.jpg','WEB_bugs/*.txt','WEB_bugs/*.json','WEB_bugs/*.png','WEB_bugs/*.jpg'],
	'templates':['*.html','assets/css/*.css','assets/js/*.js','assets/bootstrap/css/*.css','assets/img/*.png','assets/img/about/*.png','assets/img/portfolio/*.jpg','assets/img/team/*.jpg']
    }
  )


