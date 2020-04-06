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


def query_stun_server(remote_server, request, public, private, session, verbose):
    encrypted_query = utils.EncodeAES(AES.new(base64.b64decode(session), request))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_server, 54123))
        s.send(public)
        s.send(encrypted_query)
    except socket.error:
        pass


if __name__ == '__main__':
    remote = '192.236.160.95'
    # Set up Keys
    if not os.path.isfile('client_private.pem'):
        private_key = utils.create_rsa_key('client')
    else:
        private_key = utils.load_private_key('client_private.pem')
    # Import Public/Private Key Pair
    public_key = private_key.publickey()
    public_key_str = public_key.exportKey()

    # Exchange Keys with STUN Server
    session_key, stun_key = exchange_keys(remote, public_key_str, private_key, True)

    query_stun_server(remote,'this is just a test',public_key_str,private_key,session_key,True)