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


def exchange_keys(remote_server, public, private, verbose):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_server, 54123))
        remote_public_key = s.recv(4096)
        s.send(public)
        cipher_rsa = PKCS1_OAEP.new(private)
        session_key = cipher_rsa.decrypt(s.recv(1024))
        if verbose:
            print '[*] Recieved Remote Public Key and Session Key:'
            print session_key
        return session_key, remote_public_key
    except socket.error:
        print '[!!] Error During Key Exchange'
        exit()


def query_stun_server(remote_server, key, query):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_server, 54123))
        s.send(query)
        encrypted_reply = s.recv(4096) # TODO: Should this buffer be larger?
        reply = utils.DecodeAES(AES.new(base64.b64decode(key)),encrypted_reply)
    except socket.error:
        print '[!!] Error Querying Remote Server'
        pass
    return reply


def send_message(remote_server, key, recipient, message):
    cipher = AES.new(base64.b64decode(key))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_server, 54123))
        msg = '%s::::%s' % (recipient, message)
        query = utils.EncodeAES(cipher, msg)
        s.send(query)
    except socket.error:
        print '[!!] Error Querying Remote Server'
        pass


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print '[!!] No Remote Server provided'
        exit()
    else:
        remote = sys.argv[1]
    # Set up Keys
    if not os.path.isfile('client_private'):
        private_key = utils.create_rsa_key('client')
    else:
        private_key = utils.load_private_key('client_private')
    # Import Public/Private Key Pair
    public_key = private_key.publickey()
    public_key_str = public_key.exportKey()

    if not os.path.isfile('session.key'):
        # Exchange Keys with STUN Server
        session_key, stun_public = exchange_keys(remote, public_key_str, private_key, True)
        open('session.key', 'wb').write(session_key)
    else:
        session_key = open('session.key', 'rb').read()

    if '-q' in sys.argv and len(sys.argv) >= 4:
        # clear_query = utils.arr2str(sys.argv[3:])
        clear_query = sys.argv[3]
        print '[*] Sending Query: %s' % clear_query

        token = utils.cmd('sha256sum client_public').pop().split(' ')[0]
        encrypted_query = token+'>>>>'+\
                      utils.EncodeAES(AES.new(base64.b64decode(session_key)),clear_query)
        reply = query_stun_server(remote, session_key, encrypted_query)
        print '[*] Remote Server: \n%s' % reply

    if '-m' in sys.argv and len(sys.argv) >= 5:
        uname = sys.argv[3]
        message = utils.arr2str(sys.argv[4:])
        send_message(remote,session_key,uname,message)