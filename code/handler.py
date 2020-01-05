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


class Serve:
    inbound_port = 54123
    session_keys = []
    session_key = ''
    public_key = ''
    private_key = ''
    clients = []

    def __init__(self):
        self.session_key = get_random_bytes(32)
        self.socket = utils.start_listener(self.inbound_port, 5)
        self.lan_ip, self.ext_ip, self.nx_iface = self.initialize()
        self.functions = {'&?Key': self.key_exchange,
                          'SYS_CMD': self.sys_cmd}
        self.run()

    def initialize(self):
        int_ip, ext_ip, nx_iface = engine.get_public_private_ip(verbose=True)

        '''     LOAD KEYS     '''
        private_key_file = ext_ip.replace('.', '')
        if not os.path.isfile(private_key_file + '.pem'):
            self.private_key = engine.create_rsa_key(private_key_file + '.pem')
        else:
            self.private_key = engine.load_private_key(private_key_file + '.pem')
        self.public_key = self.private_key.publickey()
        return int_ip, ext_ip, nx_iface

    def run(self):
        RUNNING = True
        date, start_time = utils.create_timestamp()
        print '[*] Server Started %s - %s' % (date, start_time)
        print 'Server Functions:'
        print self.functions.keys()
        while RUNNING:
            try:
                '''        ACCEPT A CLIENT        '''
                client, client_addr = self.socket.accept()
                client_ip = client_addr[0]
                self.clients.append(client_ip)
                query = client.recv(1024)
                try:
                    decrypted_query = PKCS1_OAEP.new(self.private_key).decrypt(query)
                except ValueError:
                    pass

                if query in self.functions.keys():
                    print '[*] Replying to Query: %s' % query
                    self.functions[query](client, client_ip)
                elif query in self.functions.keys():
                    print '[*] Replying to %s API request' % client_ip
                    self.functions[query](client, client_ip, decrypted_query)

            except socket.error:
                print '[!!] Server Socket Error'
                self.socket.close()
                RUNNING = False

    def key_exchange(self, client, client_addr):
        client_key_file = client_addr.replace('.', '') + '.pem'
        client.send(self.public_key.exportKey())
        client_public_key = RSA.importKey(client.recv(4096))
        open(client_key_file, 'wb').write(client_public_key.exportKey())

        # client.send(engine_iv)
        client.close()

    def sys_cmd(self, client, client_ip, query):
        if not os.path.isfile(client_ip.replace('.', '')+'.pem'):
            print '[!!] No Public Key for client %s' % client_ip
            try:
                os.system('python client.py add %s' % client_ip)
            except OSError:
                print '[!!] Unable to Add Client PBK'
        else:
            client_key = engine.load_private_key(client_ip.replace('.', '')+'.pem')


Serve()
