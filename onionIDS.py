# -*- coding: utf-8 -*-
# @Time    : 5/24/2021 12:49 AM
# @Author  : VLBaoNgoc-SE130726
# @Email   : ngocvlbse130726@fpt.edu.vn
# @File    : test_ids.py.py
# @Software: PyCharm
import os
import sys
import time
import signal

def sigint_handler(signum, frame):
    os.system("clear")
    print("CTRL+C detected!")
    print(" \033[1;91m@Good bye\033[1;m")
    sys.exit()


signal.signal(signal.SIGINT, sigint_handler)
# Define the actual test
def logo():
    print("""\033[1;91m

             
   ___        _                 ___ ____  ____  
  / _ \ _ __ (_) ___  _ __     |_ _|  _ \/ ___| 
 | | | | '_ \| |/ _ \| '_ \     | || | | \___ \ 
 | |_| | | | | | (_) | | | |    | || |_| |___) |
  \___/|_| |_|_|\___/|_| |_|___|___|____/|____/ 
                          |_____|                                                                             
      Gen - github.com/Genethical99/ |_| v1.0
    \033[1;m """)
def menu0():
    logo()
    print("""
        1 - Linux UID
        2 - HTTP Basic Authentication 
        3 - HTTP Malware User-Agent
        4 - EXE or DLL download over HTTP
        5 - Known bad CA's
        6 - MD5 in TLS Certificate Signature
        7 - Run All
        0 - Exit
    """)
def test_uid():
    print("Start Test UID")
    os.system("curl -s 'http://testmynids.org/uid/index.html' > /dev/null")
    print("Running")
    print("Done")
def test_basicauth():
    print("Start Test BasicAuth")
    os.system("curl -s -H 'Authorization: Basic cm9vdDpyb290' testmyids.org > /dev/null")
    print("Running")
    print("Done")
def test_useragent():
    print("Start Test User_Agent")
    os.system("curl -s -A 'BlackSun' testmynids.org > /dev/null")
    os.system("curl -s -A 'HttpDownload' testmynids.org > /dev/null")
    os.system("curl -s -A 'agent' testmynids.org > /dev/null")
    os.system("curl -s -A 'MSIE' testmynids.org > /dev/null")
    os.system("curl -s -A 'JEDI-VCL' testmynids.org > /dev/null")
    print("Running")
    print("Done")
def test_exe():
    print("Start Test Download EXE ")
    os.system("curl -s 'http://testmynids.org/exe/calc.exe' -o /tmp/calc.exe")
    print("Running")
    print("Done")
def test_md5rsa() :
  # This test is made possible by Barracuda, as they still believe MD5 in certificates is OK
    ip_list = ["64.235.158.25","64.235.158.26","64.235.158.27","64.235.158.28","64.235.158.29","64.235.158.30"]
    for ip in ip_list[0:]:
        os.system("echo Q | openssl s_client -connect " + ip +":443 -tls1 > /dev/null 2>&1")
def test_badcas():
  os.system("curl -s https://edellroot.badssl.com/ > /dev/null")
  os.system("curl -s https://superfish.badssl.com/ > /dev/null")

def start_Automate():
    os.system("clear")
    menu0()
    print("Enter on of the options.")
    choice = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
    if choice == "1":
        os.system("clear")
        test_uid()
    if choice == "2":
        os.system("clear")
        test_basicauth()
    if choice == "3":
        os.system("clear")
        test_useragent()
    if choice == "4":
        os.system("clear")
        test_exe()
    if choice == "5":
        os.system("clear")
        test_badcas()
    if choice == "6":
        os.system("clear")
        test_md5rsa()
    if choice == "7":
        os.system("clear")
        test_uid()
        test_basicauth()
        test_useragent()
        test_exe()
        test_badcas()
        test_md5rsa()
    if choice == "0":
        print(" \033[1;91m@Good bye\033[1;m")
        os.system("clear")
        sys.exit()
    else:
        #print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        os.system("clear")
        start_Automate()
def rootcontrol():
    if os.geteuid() == 0:
        start_Automate()
    else:
        print("Please run it with root access.")
        sys.exit()
if __name__ == '__main__':
    rootcontrol()
