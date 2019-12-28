from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import utils
import time
import sys

BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

SESSION_KEY = base64.b64encode(get_random_bytes(16))


def connect(address, port):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((address, port))
        s.send('?')
        reply = s.recv(1024)
        s.close()
    except socket.error:
        pass
    return reply


def send(addr, port, msg):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((addr, port))
        s.send(msg)
        reply = s.recv(1024)
        s.close()
    except socket.error:
        s.close()
        pass
    return reply


if 'add' in sys.argv and len(sys.argv) >= 3:
    rmt = sys.argv[2]
    file_name = rmt.replace('.', '') + '.api_key'
    print '[*] Adding Peer %s' % rmt
    api_key = send(rmt,54123,'!?')
    print '[*] Receieved API Key: %s' % api_key
    open(file_name, 'wb').write(api_key)

if 'send' in sys.argv and len(sys.argv) >= 4:
    rmt = sys.argv[2]
    msg = utils.arr2str(sys.argv[3:])
    api_key_file = rmt.replace('.', '') + '.api_key'
    rmt_api_key = open(api_key_file, 'rb').read()
    cipher = AES.new(base64.b64decode(rmt_api_key))
    reply = send(rmt, 54123, EncodeAES(cipher, msg))
    print '[*] Received: %s' % DecodeAES(cipher, reply)
