import socket
import hashlib

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

IP = "192.168.1.15"
PORT = 1812
#PORT = 2812
#PORT = 3812

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

RADIUS_CODE = "\x01" # access-request - https://en.wikipedia.org/wiki/RADIUS#Packet_structure
SHARED_KEY = "mysupersecretsharedkeywith$ymbols"

 # [TODO] make fields in the block below dynamic
PACK_ID = "\x37"
AUTHENTICATOR = "\x20\x20\x20\x20\x20\x20\x31\x34\x38\x35\x33\x37\x35\x35\x36\x33"
AVP_USERNAME = "mrpinghe"
PASS = "aaaabaaaaaaaaaaaaaaaacaaaaaaaaaaaaaaaaaaaa"
encrypted = enc_pass(SHARED_KEY, AUTHENTICATOR, PASS)

# stuff below should be left as is
AVP_UNAME_TYPE = "\x01"
AVP_UNAME_LENGTH = len(AVP_USERNAME) + len(AVP_UNAME_TYPE) + 1 # reserve 1B for the length field itself
AVP_UNAME_LENGTH_HEX = int_to_hex(AVP_UNAME_LENGTH%256) # 256 = 2^8 = 1 byte available for length

AVP_PWD_TYPE = "\x02"
AVP_PWD_LENGTH = len(encrypted) + len(AVP_PWD_TYPE) + 1 # reserve 1B for the length field itself
AVP_PWD_LENGTH_HEX = int_to_hex(AVP_PWD_LENGTH%256) # 256 = 2^8 = 1 byte available for length

PKT_LENGTH = AVP_PWD_LENGTH + AVP_UNAME_LENGTH + len(AUTHENTICATOR) + len(PACK_ID) + len(RADIUS_CODE) + 2 # reserve 2B for the length field itself
PKT_LENGTH_HEX = int_to_hex(PKT_LENGTH%65536, 2) # 65536 = 2^16 = 2 bytes available for length


socket.sendto(RADIUS_CODE + PACK_ID + PKT_LENGTH_HEX + AUTHENTICATOR + AVP_UNAME_TYPE + AVP_UNAME_LENGTH_HEX + AVP_USERNAME + AVP_PWD_TYPE + AVP_PWD_LENGTH_HEX + encrypted, (IP, PORT))
