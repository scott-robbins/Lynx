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
        s.send(a+'  :  ' + EncodeAES(AES.new(a), DecodeAES(AES.new(a),open('pass','rb').read())))
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


def create_password():
    if os.path.isfile('pass'):
        opt = raw_input('It Looks like you already have a password. '
                        'Do you want to reset it now? (y/n):')
        if opt != ('y' or 'Y'):
            k = get_keys()
        else:
            k = get_keys()
    else:
        k = get_keys()
    pwd = EncodeAES(AES.new(k), raw_input('Enter Password: '))
    open('pass', 'wb').write(pwd)


if 'create_password' in sys.argv:
    create_password()

if 'authenticate' and len(sys.argv) >=3:
    p = sys.argv[2]
    authenticate(p)

if 'query' in sys.argv and len(sys.argv)>=4:
    rhost = sys.argv[2]
    query = sys.argv[3]

    '''     Prepare the Query '''
    print '[*] Querying %s : %s' % (rhost, query)
    k = load_key()
    # cipher = AES.new(k)
    # msg = EncodeAES(cipher, query)
    print 'Sending Encryption Key: %s' % base64.b64encode(k)

    '''     Make the Connection '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((rhost, 11235))
    s.send(base64.b64encode(k))

    ''' Now get the remote hosts key to complete handshake'''
    rkey = base64.b64decode(s.recv(1024))
    print '[*] %s Has Sent Key: %s' % (rhost, base64.b64encode(rkey))
    rfile = rhost.replace('.', '')
    open(rfile+'.key','wb').write(rkey)
    if os.path.isfile('trusted_peers.txt'):
        if rhost not in utils.swap('trusted_peers.txt',False):
            open('trusted_peers.txt','a').write(rhost)
    ciph = AES.new(rkey)
    s.send(EncodeAES(ciph, 'Querying: ' + query))
    s.close()
