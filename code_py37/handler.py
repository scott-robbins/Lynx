from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import base64
import socket
import code_py37.engine
import code_py37.utils
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

    def __init__(self, mode):
        self.session_key = get_random_bytes(32)
        self.socket = code_py37.utils.start_listener(self.inbound_port, 7)
        self.lan_ip, self.ext_ip, self.nx_iface = self.initialize()
        self.functions = {'&?Key': self.key_exchange,
                          'SYS_CMD': self.sys_cmd,
                          'GET_FILE': self.get_file,
                          'PUT_FILE': self.put_file}
        self.run(mode)

    def initialize(self):
        int_ip, ext_ip, nx_iface = code_py37.engine.get_public_private_ip(verbose=True)

        '''     LOAD KEYS     '''
        private_key_file = ext_ip.replace('.', '')
        if not os.path.isfile(private_key_file + '.pem'):
            self.private_key = code_py37.engine.create_rsa_key(private_key_file + '.pem')
        else:
            self.private_key = code_py37.engine.load_private_key(private_key_file + '.pem')
        self.public_key = self.private_key.publickey()
        return int_ip, ext_ip, nx_iface

    def run(self, MODE):
        RUNNING = True
        tic = time.time()
        date, start_time = code_py37.utils.create_timestamp()
        print('\033[1m[*] \033[32mServer Started\033[0m\033[1m %s - %s\033[0m' % (date, start_time))

        while RUNNING:
            try:
                '''        ACCEPT A CLIENT        '''
                client, client_addr = self.socket.accept()
                client_ip = client_addr[0]
                self.clients.append(client_ip)
                query = client.recv(1024)

                try:
                    decrypted_query = PKCS1_OAEP.new(self.private_key).decrypt(query)
                    print(decrypted_query)
                    query = decrypted_query.split(' : ')[0]
                    command = decrypted_query.split(' : ')[1]
                except ValueError:
                    pass

                if query == '&?Key':
                    print('[*] Initializing Handshake with new client %s' % query)
                    self.functions[query](client, client_ip)
                elif query in self.functions.keys():
                    print('[*] Replying to API request from \033[1m%s\033[0m' % client_ip)
                    self.functions[query](client, client_ip, command)
                else:
                    client.close()
            except socket.error:
                print('\033[31m\033[1m[!!] Server Socket Error\033[0m')
                self.socket.close()
                RUNNING = False
            except KeyboardInterrupt:
                print('\n\033[1m[!!] \033[31mServer KILLED \033[0m\033[1m[%ss Elapsed]\033[0m' %\
                      str(time.time()-tic))
                self.socket.close()
                RUNNING = False

    def key_exchange(self, client, client_addr):
        client_key_file = client_addr.replace('.', '') + '.pem'
        client.send(self.public_key.exportKey())
        client_public_key = RSA.importKey(client.recv(4096))
        open(client_key_file, 'wb').write(client_public_key.exportKey())
        client.send(base64.b64encode(self.session_key))
        client.close()

    def sys_cmd(self, client, client_ip, query):
        self.check_client(client_ip)
        client_key = code_py37.engine.load_private_key(client_ip.replace('.', '') + '.pem')
        status = code_py37.utils.arr2lines(code_py37.utils.cmd(query))
        print('$ %s' % query)
        print('$ %s' % status)
        key = get_random_bytes(32)
        encrypted_key = PKCS1_OAEP.new(client_key).encrypt(key)
        encrypted_reply = code_py37.utils.EncodeAES(AES.new(key),status)
        client.send(encrypted_key+'::::'+encrypted_reply)
        client.close()

    def get_file(self, client, client_ip, query):
        self.check_client(client_ip)
        client_key = code_py37.engine.load_private_key(client_ip.replace('.','')+'.pem')
        file_size = os.path.getsize(query.replace(' ', ''))
        print('[*] Sending %s to %s [%d bytes]' % (query, client_ip, file_size))
        # print '[*] %s is %d bytes' % (query, file_size)
        content = open(query.replace(' ',''), 'rb').read()
        key = get_random_bytes(32)
        # print '[*] Encryption Key: %s' % base64.b64encode(key)
        encrypted_key = PKCS1_OAEP.new(client_key).encrypt(key)
        client.send(encrypted_key+'::::'+code_py37.utils.EncodeAES(AES.new(key), content))
        client.close()

    def put_file(self, client, client_ip, query):
        tic = time.time()
        self.check_client(client_ip)
        client_key = code_py37.engine.load_private_key(client_ip.replace('.', '') + '.pem')
        file_name = query.split(' = ')[0]
        file_size = int(query.split(' = ')[1])
        print('[*] %s is sending %s [%d bytes]' % (client_ip, file_name, file_size))
        raw_data = client.recv(file_size + 40)
        client.close()  # Get key and encrypted file in one reply
        key = client_key.decrypt(raw_data.split(';;;;')[0])
        encrypted_data = raw_data.split(';;;;')[1]
        decrypted_data = code_py37.utils.DecodeAES(AES.new(key), encrypted_data)
        if os.path.isfile(file_name):
            if input('[!!] %s Already Exists, do you want to Overwrite it (y/n)?: '%file_name).upper() == 'Y':
                os.remove(file_name)
        open(file_name, 'wb').write(decrypted_data)
        bytes_transferred = os.path.getsize(file_name)
        print('[*] %d Bytes transferred [%ss Elapsed]' % (bytes_transferred, str(time.time()-tic)))

    def check_client(self, ip):
        if not os.path.isfile(ip.replace('.', '') + '.pem'):
            print('[!!] No Public Key for client %s' % ip)
            try:
                os.system('python client.py add %s' % ip)
            except OSError:
                print('[!!] Unable to Load Client Public Key')


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        server_mode = sys.argv[2]
    else:
        server_mode = 'listener'
    Serve(mode=server_mode)

