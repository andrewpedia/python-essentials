# -*- coding: utf-8 -*-
import argparse
import hashlib
import select
import socket
import textwrap

import aaaScan as ps
import nmap
from scapy.all import *
from tacacs_plus.client import TACACSClient


def int_to_hex(num, least_num_of_byte=1):
    hex_length = 2 * least_num_of_byte + 2
    return "{0:#0{1}x}".format(num, hex_length)[2:].decode("hex")


# 加密处理
def encrypt_pass(shared_key, authenticator, password):
    chunk_size = 16

    pass_ary = [
        password[i : i + chunk_size] for i in range(0, len(password), chunk_size)
    ]
    final = ""

    for chunk in pass_ary:
        if len(chunk) < chunk_size:
            chunk = (chunk.encode("hex") + "00" * (chunk_size - len(chunk))).decode(
                "hex"
            )
        md5 = hashlib.md5()
        try:
            xor
            md5.update(shared_key + xor)
        except NameError:
            md5.update(shared_key + authenticator)

        IV = md5.hexdigest()
        xor = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(chunk, IV.decode("hex")))
        final += xor

    return final


class PortScanner:
    # 默认线程个数
    __thread_limit = 1000
    # 默认delay
    __delay = 10

    @classmethod
    def __usage(cls):
        print("python tcp udp Scanner v0.1")

    def __init__(self, type, beginport, portnum):
        """
        起始端口+端口个数
        """
        self._type = type
        self._beginport = beginport
        self._portnum = portnum
        self.tacacsfile = None
        self.radiusfile = None

    def radiuscrack(self, localsocket, ip, port_number):
        print("radiuscrack " + str(port_number))
        radius_code = "\x01"
        authenticator = (
            "\x20\x20\x20\x20\x20\x20\x31\x34\x38\x35\x33\x37\x35\x35\x36\x33"
        )
        pack_id = int_to_hex(1 % 256)
        pwd = "testing"
        user = "user1"
        avp_pwd_type = "\x02"
        encrypted = encrypt_pass("secret", authenticator, pwd)
        avp_pwd_len = len(encrypted) + len(avp_pwd_type) + 1
        avp_pwd_len_hex = int_to_hex(avp_pwd_len % 256)
        avp_uname_type = "\x01"
        avp_uname_len = len(user) + len(avp_uname_type) + 1
        avp_uname_len_hex = int_to_hex(avp_uname_len % 256)
        pkt_len = (
            avp_pwd_len
            + avp_uname_len
            + len(authenticator)
            + len(pack_id)
            + len(radius_code)
            + 2
        )
        pkt_len_hex = int_to_hex(pkt_len % 65536, 2)

        localsocket.sendto(
            radius_code
            + pack_id
            + pkt_len_hex
            + authenticator
            + avp_uname_type
            + avp_uname_len_hex
            + user
            + avp_pwd_type
            + avp_pwd_len_hex
            + encrypted,
            (ip, int(port_number)),
        )
        ready = select.select([localsocket], [], [], 5)

        if ready[0]:
            resp_hex = localsocket.recv(2048).encode("hex")
            print(resp_hex)
            resp_code = resp_hex[:2]
            print("resp_code " + resp_code)
            if (
                resp_code == "01" or resp_code == "02" or resp_code == "03"
            ):  # radius service is on
                content = (
                    "***************found radius service *******************"
                    + str(port_number)
                )
                print(content)
                try:
                    self.radiusfile.write(content)
                except Exception as e:
                    print(e)

                localsocket.close()
                return True
            else:
                localsocket.close()
                return False
        else:
            localsocket.close()
            print(str(port_number) + " Timeout ")
            return False

    def scan(self, server_ip, message=""):
        """"""

        start_time = time.time()
        output = self.__scan_ports(server_ip, self.__delay, message.encode("utf-8"))
        stop_time = time.time()

        print(
            "server {} scanned in  {} seconds".format(server_ip, stop_time - start_time)
        )
        print("scan finished !\n")

        return output

    def set_thread_limit(self, limit):
        """"""
        limit = int(limit)

        if limit <= 0 or limit > 50000:

            print("param not correct, will use default thread limit 1,000.")
            return

        self.__thread_limit = limit

    def set_delay(self, delay):
        """"""
        delay = int(delay)
        if delay <= 0 or delay > 100:

            print("not correct param, use the default delay time 10 seconds.")
            return

        self.__delay = delay

    def show_delay(self):

        print("Current timeout delay is {} seconds.".format(self.__delay))
        return self.__delay

    def __scan_ports_helper(self, ip, delay, tcpoutput, udpoutput, message):
        """
        多线程扫描
        """
        port_index = 0

        self.tacacsfile = open("tacacs.txt", "w+")
        self.radiusfile = open("radius.txt", "w+")

        while port_index < self._portnum:
            # Ensure the number of concurrently running threads does not exceed the thread limit
            while (
                threading.activeCount() < self.__thread_limit
                and port_index < self._portnum
            ):
                # Start threads
                if int(self._type) == 1:
                    thread = threading.Thread(
                        target=self.__TCP_connect,
                        args=(
                            ip,
                            self._beginport + port_index,
                            delay,
                            tcpoutput,
                            message,
                            self.tacacsfile,
                        ),
                    )
                else:
                    thread = threading.Thread(
                        target=self.__UDP_connect,
                        args=(
                            ip,
                            self._beginport + port_index,
                            delay,
                            udpoutput,
                            message,
                            self.radiusfile,
                        ),
                    )
                thread.start()
                port_index = port_index + 1
            time.sleep(0.01)

    def __scan_ports(self, ip, delay, message):

        tcpoutput = {}
        udpoutput = {}

        thread = threading.Thread(
            target=self.__scan_ports_helper,
            args=(ip, delay, tcpoutput, udpoutput, message),
        )
        thread.start()

        done = 0

        # 检测已经处理的端口数量
        while done < self._portnum:
            if self._type == 1:
                done = len(tcpoutput)
            else:
                done = len(udpoutput)

            print("done: " + str(done))
            time.sleep(0.01)
            continue

        try:
            self.tacacsfile.close()
            self.radiusfile.close()
        except Exception as e:
            print(e)

        return tcpoutput, udpoutput

    def tacacscrack(self, ip, port_number, tcpoutput):
        try:
            username = "test"
            password = "123456"
            secretkey = "testing"

            print("sproof auth with port_number:" + str(port_number))
            cli = TACACSClient(
                ip, port_number, secretkey, timeout=10, family=socket.AF_INET
            )
            authen = cli.authenticate(username, password)
            print(authen.valid)
            if True == authen.valid or False == authen.valid:
                print(
                    "***************found tacacs+ service *******************"
                    + str(port_number)
                )
                content = "***************found tacacs+ service ******************* {0}".format(
                    str(port_number)
                )

                self.tacacsfile.write(content)
                tcpoutput[port_number] = "ON"
            else:
                tcpoutput[port_number] = "CLOSE"
        except Exception as e:
            print("auth exception" + str(port_number))
            tcpoutput[port_number] = "CLOSE"
            print(e.message)
            pass

    def __TCP_connect(self, ip, port_number, delay, tcpoutput, message, tacacsfile):
        """
        通过tcp socket 连接状态检测
        """
        try:
            TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            TCP_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            TCP_sock.settimeout(delay)
            result = TCP_sock.connect_ex((ip, int(port_number)))

            if result == 0:
                self.tacacscrack(ip, port_number, tcpoutput)
            else:
                tcpoutput[port_number] = "CLOSE"

            TCP_sock.close()

        except Exception as e:
            tcpoutput[port_number] = "CLOSE"
            pass

    def __UDP_connect(self, ip, port_number, delay, udpoutput, message, radiusfile):
        """
        udp连接状态
        """

        try:
            nm = nmap.PortScanner()
            print("scan " + str(ip) + ":" + str(port_number))

            nm.scan(ip + "/32", arguments=" -p " + str(port_number) + " -sU ")
            hosts_list = [
                (port_number, nm[x][u"udp"][port_number]["state"])
                for x in nm.all_hosts()
            ]

            for host, status in hosts_list:
                print("{0}:{1}".format(host, status))

            if "open" in status:
                print(str(port_number) + " is online")
                localsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                localsocket.setblocking(0)
                self.radiuscrack(localsocket, ip, port_number)
                udpoutput[port_number] = "OPEN"
            else:
                udpoutput[port_number] = "closed"

        except Exception as e:
            print("udp exception " + str(e))
            # import traceback
            # traceback.print_stack()
            udpoutput[port_number] = "CLOSE"
            pass


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""port scanner multithread. """),
    )

    parser.add_argument(
        "-t", "--type", dest="type", type=int, help="type", required=True, default=1
    )
    parser.add_argument("-H", "--host", dest="host", help="hostip", required=True)
    parser.add_argument(
        "-b", "--beginport", type=int, dest="beginport", help="beginport", required=True
    )
    parser.add_argument(
        "-n", "--portnum", type=int, dest="portnum", help="portnum", required=True
    )
    args = parser.parse_args()

    print("start scan port from " + str(args.beginport) + " num :" + str(args.portnum))
    message = "some"
    scanner = ps.PortScanner(args.type, (args.beginport), (args.portnum))
    scanner.set_thread_limit(100)
    scanner.set_delay(10)
    scanner.show_delay()
    scanner.scan(args.host, message)


if __name__ == "__main__":

    main()
