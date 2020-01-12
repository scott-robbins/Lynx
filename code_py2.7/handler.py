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

    def __init__(self, mode):
        self.session_key = get_random_bytes(32)
        self.socket = utils.start_listener(self.inbound_port, 7)
        self.lan_ip, self.ext_ip, self.nx_iface = self.initialize()
        self.functions = {'&?Key': self.key_exchange,
                          'SYS_CMD': self.sys_cmd,
                          'GET_FILE': self.get_file,
                          'PUT_FILE': self.put_file}
        self.run(mode)

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

    def run(self, MODE):
        RUNNING = True
        tic = time.time()
        date, start_time = utils.create_timestamp()
        print '\033[1m[*] \033[32mServer Started\033[0m\033[1m %s - %s\033[0m' % (date, start_time)

        while RUNNING:
            try:
                '''        ACCEPT A CLIENT        '''
                client, client_addr = self.socket.accept()
                client_ip = client_addr[0]
                self.clients.append(client_ip)
                query = client.recv(1024)
                print '[*] %s Has Connected' % client_ip
                try:
                    decrypted_query = PKCS1_OAEP.new(self.private_key).decrypt(query)
                    print decrypted_query

                    query = decrypted_query.split(' : ')[0]
                    command = decrypted_query.split(' : ')[1]
                except ValueError:
                    pass
                except UnboundLocalError:
                    print '\033[31m[*] Failed to Decrypt Query From %s\033[0m' % client_ip

                if query == '&?Key':
                    print '[*] Initializing Handshake with new client %s' % query
                    self.functions[query](client, client_ip)
                elif query in self.functions.keys():
                    print '[*] Replying to API request from \033[1m%s\033[0m' % client_ip
                    try:
                        self.functions[query](client, client_ip, command)
                    except KeyError:
                        self.functions[query](client, client_ip, command)
                        pass
                else:
                    client.close()
            except socket.error:
                print '\033[31m\033[1m[!!] Server Socket Error\033[0m'
                self.socket.close()
                RUNNING = False
            except KeyboardInterrupt:
                print '\n\033[1m[!!] \033[31mServer KILLED \033[0m\033[1m[%ss Elapsed]\033[0m' %\
                      str(time.time()-tic)
                self.socket.close()
                RUNNING = False
                os.system('sh cleaner.sh')

    def key_exchange(self, client, client_addr):
        client_key_file = client_addr.replace('.', '') + '.pem'
        client.send(self.public_key.exportKey())
        client_public_key = RSA.importKey(client.recv(4096))
        open(client_key_file, 'wb').write(client_public_key.exportKey())
        client.send(base64.b64encode(self.session_key))
        client.close()

    def sys_cmd(self, client, client_ip, query):
        self.check_client(client_ip)
        client_key = engine.load_private_key(client_ip.replace('.', '') + '.pem')
        status = utils.arr2lines(utils.cmd(query))
        print '$ %s' % query
        print '$ %s' % status
        key = get_random_bytes(32)
        encrypted_key = PKCS1_OAEP.new(client_key).encrypt(key)
        encrypted_reply = utils.EncodeAES(AES.new(key),status)
        client.send(encrypted_key+'::::'+encrypted_reply)
        client.close()

    def get_file(self, client, client_ip, query):
        self.check_client(client_ip)
        client_key = engine.load_private_key(client_ip.replace('.','')+'.pem')
        file_size = os.path.getsize(query.replace(' ', ''))
        print '[*] Sending %s to %s [%d bytes]' % (query, client_ip, file_size)
        # print '[*] %s is %d bytes' % (query, file_size)
        content = open(query.replace(' ',''), 'rb').read()
        key = get_random_bytes(32)
        # print '[*] Encryption Key: %s' % base64.b64encode(key)
        encrypted_key = PKCS1_OAEP.new(client_key).encrypt(key)
        client.send(encrypted_key+'::::'+utils.EncodeAES(AES.new(key), content))
        client.close()

    def put_file(self, client, client_ip, query):
        tic = time.time()
        self.check_client(client_ip)
        client_key = engine.load_private_key(client_ip.replace('.', '') + '.pem')
        file_name = query.split(' = ')[0]
        file_size = int(query.split(' = ')[1])
        print '[*] %s is sending %s [%d bytes]' % (client_ip, file_name, file_size)
        print '[*] Recieving [%d bytes]' % (file_size)

        encrypted_data = client.recv(file_size+50)
        print '[*] Decrypting %d characters of encrypted data' % len(encrypted_data)
        encrypted_key = encrypted_data.split(' ;;;; ')[0]
        cipher_text = encrypted_data.split(' ;;;; ')[1]

        key = PKCS1_OAEP.new(self.private_key).decrypt(encrypted_key)
        decrypted_data = utils.DecodeAES(AES.new(key), cipher_text)
        if os.path.isfile(query):
            if raw_input('[!!] %s Already Exists, do you want to Overwrite it (y/n)?: ' % query).upper() == 'Y':
                os.remove(query)
        resource = query.split(': ')[1]
        open(resource, 'wb').write(decrypted_data)

        print '[*] %d Bytes transferred [%ss Elapsed]' % (file_size, str(time.time()-tic))

    def check_client(self, ip):
        if not os.path.isfile(ip.replace('.', '') + '.pem'):
            print '[!!] No Public Key for client %s' % ip
            try:
                os.system('python client.py add %s' % ip)
            except OSError:
                print '[!!] Unable to Load Client Public Key'


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        server_mode = sys.argv[2]
    else:
        server_mode = 'listener'
    os.system('sh cleaner.sh')
    Serve(mode=server_mode)
