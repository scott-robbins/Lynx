from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from threading import Thread
import base64
import socket
import utils
import time
import sys
import os


remote_server = '192.236.160.95'
# Set up Keys
if not os.path.isfile('client_private.pem'):
    private_key = utils.create_rsa_key('client')
else:
    private_key = utils.load_private_key('client_private.pem')

public_key = private_key.publickey()
public_key_str = public_key.exportKey()

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((remote_server, 54123))
remote_public_key = s.recv(4096)
s.send(public_key_str)
s.connect()

print 'Recieved Remote Public Key: '
print remote_public_key

