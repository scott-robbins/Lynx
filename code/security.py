from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import random
import utils
import sys
import os


#  ################# Crypto Constants ################ #
BLOCK_SIZE = 16;            PADDING = '{'
#   ################ Lambda Functions  ################   #
Pad = lambda sr: sr + (BLOCK_SIZE - len(sr) % BLOCK_SIZE) * PADDING        # pad the text to be encrypted
EncodeAES = lambda c, st: base64.b64encode(c.encrypt(Pad(st)))            # encrypt with AES, encode with base64
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
#  ###################################################### #


def get_keys():
    if os.path.isfile('secret'):
        opt = raw_input('It looks like you might already have keys configured. ' \
                        'Do you want to overwrite them? (y/n): ')
        if opt == ('y' or 'Y'):
            os.remove('secret')
        else:
            return base64.b64decode(open('secret', 'rb').read())

    key = get_random_bytes(32)
    open('secret', 'wb').write(base64.b64encode(key))
    return key


def create_password():
    if os.path.isfile('pass'):
        opt = raw_input('It Looks like you already have a password. Do you want to reset it now? (y/n):')
        if opt != ('y' or 'Y'):
            return False
    k = get_keys()
    pwd = EncodeAES(AES.new(k), raw_input('Enter Password: '))
    open('pass', 'wb').write(pwd)


def load_password():
    if not os.path.isfile('pass'):
        print '[!!] No password file found'
        return ''
    if not os.path.isfile('secret'):
        print '[!!] No Secret file found'
        return ''
    k = base64.b64decode(open('secret', 'rb').read())
    return DecodeAES(AES.new(k), open('pass').read())


def authenticate(peer):
    ''' DEBUGGING ONLY '''
    try:
        a = base64.b64decode(open('secret').read())
    except IOError:
        print '!! No Secret File'
    try:
        b = open('pass').read()
    except IOError:
        print '!! No Key File'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((peer, 11235))
        s.send(a+'  :  ' + EncodeAES(AES.new(a), 'test_password'))
        print s.recv(1024)
        s.close()
    except socket.error:
        print '[!!] Connection Error'
        exit()


def retrieve_credentials(node):
    file_name = node.replace('.', '')
    key = base64.b64decode(utils.swap(file_name+'.key', False).pop())
    pwd = DecodeAES(AES.new(key), utils.swap(file_name+'.pwd', False).pop())
    return pwd, key


def log_credentials(client, credentials, key):
    open('trusted_peers.txt', 'a').write(client)
    # TODO: Get Remote clients keys and write those, then use trusted_peers
    #  To be able to associate that with the remote peer for easier setup
    fname = client.replace('.', '')
    open(fname + '.key','w').write(base64.b64encode(key))
    open(fname + '.pwd','w').write(EncodeAES(AES.new(key), credentials))


def load_key():
    return base64.b64decode(open('secret').read())


if 'auth_test_0' and len(sys.argv) >=3:
    p = sys.argv[2]
    authenticate(p)


