from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import random
import base64
import socket
import utils
import time
import sys
import os


def calculate_token(remote_public_key, verbose):
    rmt_head64 = utils.arr2str(list(remote_public_key.split('\n')[1:8]))
    rmt_token = SHA256.new(rmt_head64).hexdigest()[0:32]
    if verbose:
        print '[*] Token Calculated: %s' % rmt_token
    return rmt_token


def query(ip_addr, rmt_port, question):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_addr, rmt_port))
        s.send(question)
        reply = s.recv(4096)
    except socket.error:
        print '[!!] Connection Error... Query Failed!'
        s.close()
        return False, False
    return reply, s


local_ip = utils.get_local_ip()
peer_keys = {}

if len(sys.argv) > 2 and 'test' in sys.argv:
    ip = sys.argv[2]
    port = int(sys.argv[3])
    rmt_pbk, s = query(ip, port, '?')
    if rmt_pbk and os.path.isfile('KEYS/public.pem'):
        pbk = open('KEYS/public.pem', 'rb').read()
        s.send(pbk)
    elif rmt_pbk:
        public_key = utils.create_ephemeral_key()
        head64 = utils.arr2str(list(public_key.exportKey().split('\n')[1:8]))
        token = SHA256.new(head64).hexdigest()[0:32]
        s.send(public_key.exportKey())
        print token
    s.close()
    print 'Key Exchange Complete!'
    rmt_token = calculate_token(remote_public_key=rmt_pbk, verbose=True)
    new_port = int(raw_input('Enter New Port: '))
    files, srvr = query(ip, new_port, '?'+rmt_token)
    print '[*] %s' % files
    srvr.close()
    new_port = int(raw_input('Enter New Port: '))
    print 'Testing File Transfer...'
    file_data, c = query(ip, new_port,'?'+rmt_token+':test.txt')
    open('test.txt', 'w').write(file_data)
    c.close()
