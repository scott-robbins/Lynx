from Crypto.Hash import SHA256
from Crypto.Cipher import AES
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
    passphrase = ''
    SECURE = False

    def __init__(self, port, isSecure):
        self.SECURE = isSecure[0]
        self.passphrase = isSecure[1]
        self.crypto_engine = self.initialize(port)
        self.actions = {'?': self.exchange_public_keys,
                        '?'+self.token: self.show_available_files,
                        '?'+self.token+':': self.file_download,
                        '!'+self.token+':': self.file_upload}
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
                    listen, new_port = utils.create_listening_socket(self.inbound_port, True)
                    client, addr = listen.accept()
                    query = client.recv(1024)
                    self.clients.append(addr[0])
                    if query in self.actions.keys():
                        self.actions[query](query, client, addr[0])
                    elif len(query.split('?'+self.token+':'))>1:
                        q = '?'+self.token+':'
                        self.actions[q](query, client, addr[0])
                    elif len(query.split('!'+self.token+':'))>1:
                        q = '!'+self.token+':'
                        self.actions[q](query, client, addr[0])
                    else:
                        print '[!!] Received unrecognized query'
                        print query
                        client.close()
                    self.inbound_port = new_port
                except socket.error:
                    print '[!!] Failed to Start Server'
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

    def exchange_public_keys(self, query, client, addr):
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
        self.inbound_port = random.randint(1025, 65000)
        client.send(str(self.inbound_port))
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

    def show_available_files(self, query, client, addr):
        if os.path.isdir('Shared/'):
            # Count the number of objects and report back to client
            reply = '%d Files in Shared/' % len(os.listdir('Shared'))

        else:
            reply = '[!!] No Shared Folder!'
        print reply
        client.send(reply)
        answer = client.recv(4096)
        self.inbound_port = random.randint(1025, 65000)
        client.send(str(self.inbound_port))
        client.close()
        return answer

    def file_download(self, query, client, addr):
        """
        File_Download will download a file ONTO the machine running server.py
        :param query:
        :param client:
        :param addr:
        :return:
        """
        if len(query.split(' ')) == 2:
            query_str = query.split(':')[0]
            file_name = query.split(' ')[1]
            print '[*] %s is requesting %s' % (addr, file_name)
        if not self.SECURE:
            if file_name in os.listdir('Shared/') or os.path.isfile(file_name):
                client.send(open(file_name, 'rb').read())
            else:
                print '[!!] Cannot Find %s' % file_name
                client.close()
        else:
            if file_name in os.listdir('Shared/') or os.path.isfile(file_name):
                plain_text = open(file_name, 'rb').read()
                cipher_text = utils.EncodeAES(AES.new(self.passphrase), plain_text)
                client.send(cipher_text)
            else:
                print '[!!] Cannot Find %s' % file_name
                client.close()
        # For debugging that the files are transferring correctly
        os.system('sha256sum %s' % file_name)
        self.inbound_port = random.randint(1025, 65000)
        client.send(str(self.inbound_port))
        client.close()
        return client

    def file_upload(self, query, client, addr):
        if len(query.split(' ')) == 3:
            remote_file_name = query.split(' ')[1]
            remote_file_size = int(query.split(' ')[2])*2
            # if remote_file_size > 100000000:
            #     remote_file_size = 1000000
            client.send(str(remote_file_size))
            print '[*] %s is uploading %s' % (addr, remote_file_name)
        print remote_file_size
        file_data = client.recv(remote_file_size)
        open(remote_file_name, 'w').write(file_data)
        size_transferred = os.path.getsize(remote_file_name)
        print '[*] %s Uploaded [%d bytes]' % \
              (remote_file_name, size_transferred)
        os.system('sha256sum %s' % remote_file_name)
        self.inbound_port = random.randint(1025, 65000)
        client.send(str(self.inbound_port))
        client.close()
        return size_transferred


if '-p' not in sys.argv:
    Server(port=12345, isSecure=[False, ''])
elif len(sys.argv) == 3:
    Server(port=12345, isSecure=[True, sys.argv[2]])

