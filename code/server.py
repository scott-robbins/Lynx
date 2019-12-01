from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import random
import socket
import utils
import time
import sys
import os


class Server:
    start = 0.0
    uptime = 0.0
    token = ''
    clients = []
    inbound_port = 0
    outgoin_port = 0

    def __init__(self, port):
        self.crypto_engine = self.initialize(port)
        self.actions = {'?': self.exchange_public_keys,
                        '?'+self.token: self.show_available_files}
        self.start_listener()

    def initialize(self, p):
        self.start = time.time()
        self.inbound_port = p
        self.calculate_uptime()
        self.delete_keys(True)                      # Clear out any old keys
        public_key = utils.create_ephemeral_key()   # Configure a Public/Private Key pair
        head64 = utils.arr2str(list(public_key.exportKey().split('\n')[1:8]))
        self.token = SHA256.new(head64).hexdigest()[0:32]
        print '[*] Setting Token to: %s' % self.token
        return AES.new(self.token)

    def calculate_uptime(self):
        dt = time.time() - self.start
        self.uptime = dt
        return dt

    def start_listener(self):
        listening = True
        try:
            while listening:
                try:
                    listen, self.inbound_port = utils.create_listening_socket(self.inbound_port, True)
                    client, addr = listen.accept()
                    query = client.recv(1024)
                    self.clients.append(addr[0])
                    if query in self.actions.keys():
                        self.actions[query](client, addr[0])
                    else:
                        print '[!!] Received unrecognized query'
                        client.close()
                except socket.error:
                    print '[!!] Could Start Server'
                    listening = False
        except KeyboardInterrupt:
            try:    # Try to close any sockets that could be open?
                listen.close()
                client.close()
            except:
                pass
            print '\n\033[1m\033[31m[!!] Server KILLED \033[0m\033[1m[%ss Elapsed]\033[0m' %\
                str(self.calculate_uptime())
            self.delete_keys(True)

    def exchange_public_keys(self, client, addr):
        try:
            pbk = open('KEYS/public.pem', 'rb').read()
            client.send(pbk)
            client_pbk_file = addr.replace('.', '') + '.pem'
            reply = client.recv(4096)
        except socket.error:
            print '[!!] Key Exchange Failed'
            client.close()
            return False
        open(client_pbk_file, 'wb').write(reply)
        print '[*] Key Exchange completed with %s' % addr
        client.close()
        return True

    def delete_keys(self, verbosity):
        if os.path.isfile('KEYS/private.pem'):
            os.remove('KEYS/private.pem')
            if verbosity:
                print '[*] Private Key Deleted'
        if os.path.isfile('KEYS/public.pem'):
            os.remove('KEYS/public.pem')
            if verbosity:
                print '[*] Public Key Deleted'
        if os.path.isdir('KEYS'):
            os.rmdir('KEYS')

    def show_available_files(self, client, addr):
        if os.path.isdir('Shared/'):
            # Count the number of objects and report back to client
            reply = '%d Files in Shared/' % len(os.listdir('Shared'))

        else:
            reply = '[!!] No Shared Folder!'
        print reply
        client.send(reply)
        answer = client.recv(4096)
        return answer
Server(12345)
