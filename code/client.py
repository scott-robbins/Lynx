from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import base64
import socket
import engine
import utils
import time
import sys
import os

'''
Algorithm 	Sender uses: 	Receiver uses:
Encryption 	Public key 	    Private key
Signature 	Private key 	Public key
'''

default_port = 54123
lan_ip, ext_ip, nx_nic = engine.get_public_private_ip(verbose=True)
private_key = engine.load_private_key(ext_ip.replace('.','')+'.pem')
public_key = private_key.publickey()
DEBUG = True


def add_remote_host_public_key(remote_host, remote_key_file):
    session_key = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_host, default_port))
        s.send('&?Key')
        rmt_pub_key = s.recv(4096)
        open(remote_key_file, 'wb').write(rmt_pub_key)
        s.send(public_key.exportKey())
        session_key = s.recv(4096)
        open(remote_host.replace('.','')+'.token','wb').write(session_key)
        s.close()
    except socket.error:
        s.close()
        print '[!!] Connection Broken'
    return session_key


if 'add' in sys.argv and len(sys.argv) >= 3:
    rmt = sys.argv[2]
    rmt_key = rmt.replace('.', '') + '.pem'
    key = add_remote_host_public_key(rmt, rmt_key)
    open(rmt.replace('.', '') + '.token', 'wb').write(key)
    print '[*] Keys Exchanged With %s' % rmt

