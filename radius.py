#!/usr/bin/env python

import socket
import hashlib
import argparse
import re
import textwrap

'''
TODO
- take a list of passwords
- take a list of shared secret
- generate random PACK_ID (%256)
- generate random AUTHENTICATOR
'''

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def int_to_hex(num, least_num_of_byte = 1):
    hex_length = 2*least_num_of_byte + 2
    return "{0:#0{1}x}".format(num, hex_length)[2:].decode("hex")

# https://tools.ietf.org/html/rfc2865#page-27
def enc_pass(shared_key, authenticator, password):
    CHUNK_SIZE = 16

    pass_ary = [password[i:i+CHUNK_SIZE] for i in range(0, len(password), CHUNK_SIZE)]
    final = ""

    for chunk in pass_ary:
        if len(chunk) < CHUNK_SIZE:
            chunk = (chunk.encode("hex") + "00" * (CHUNK_SIZE - len(chunk))).decode("hex")
        md5 = hashlib.md5()
        try:
            xor
            # subsequent run, chunk n xor MD5(shared key + chunk n-1)
            md5.update(shared_key + xor)
        except NameError:
            # first run, chunk1 xor MD5(shared key + authenticator)
            md5.update(shared_key + authenticator)

        IV = md5.hexdigest()
        xor = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(chunk, IV.decode("hex")))
        final += xor

    return final


parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, 
    description=textwrap.dedent('''\
        %sRadius Fuzzer - v1.0
        An utility tool to brute force authentication service using Radius protocal%s
    ''' % (bcolors.OKGREEN, bcolors.ENDC)))

parser.add_argument('ip', metavar="IP", help="Required. The IP address where the radius service is running")
parser.add_argument('-P', '--port', dest="port", help="The port of the radius service. Default 1812", default=1812)
parser.add_argument('-p', '--password', dest="password", help="Required. The password to be used", required=True)
parser.add_argument('-u', '--username', dest="user", help="Required. The username to be used", required=True)
parser.add_argument('-s', '--secret', dest="secret", help="Required. The shared secret to be used", required=True)

args = parser.parse_args()


socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

RADIUS_CODE = "\x01" # access-request - https://en.wikipedia.org/wiki/RADIUS#Packet_structure
# SHARED_KEY = "mysupersecretsharedkeywith$ymbols"

PACK_ID = "\x37"
AUTHENTICATOR = "\x20\x20\x20\x20\x20\x20\x31\x34\x38\x35\x33\x37\x35\x35\x36\x33"
# AVP_USERNAME = "mrpinghe"
# PASS = "aaaabaaaaaaaaaaaaaaaacaaaaaaaaaaaaaaaaaaaa"
encrypted = enc_pass(args.secret, AUTHENTICATOR, args.password)

# stuff below should be left as is
AVP_UNAME_TYPE = "\x01"
AVP_UNAME_LENGTH = len(args.user) + len(AVP_UNAME_TYPE) + 1 # reserve 1B for the length field itself
AVP_UNAME_LENGTH_HEX = int_to_hex(AVP_UNAME_LENGTH%256) # 256 = 2^8 = 1 byte available for length

AVP_PWD_TYPE = "\x02"
AVP_PWD_LENGTH = len(encrypted) + len(AVP_PWD_TYPE) + 1 # reserve 1B for the length field itself
AVP_PWD_LENGTH_HEX = int_to_hex(AVP_PWD_LENGTH%256) # 256 = 2^8 = 1 byte available for length

PKT_LENGTH = AVP_PWD_LENGTH + AVP_UNAME_LENGTH + len(AUTHENTICATOR) + len(PACK_ID) + len(RADIUS_CODE) + 2 # reserve 2B for the length field itself
PKT_LENGTH_HEX = int_to_hex(PKT_LENGTH%65536, 2) # 65536 = 2^16 = 2 bytes available for length


socket.sendto(RADIUS_CODE + PACK_ID + PKT_LENGTH_HEX + AUTHENTICATOR + AVP_UNAME_TYPE + AVP_UNAME_LENGTH_HEX + args.user + AVP_PWD_TYPE + AVP_PWD_LENGTH_HEX + encrypted, (args.ip, args.port))

