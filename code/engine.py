from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import random
import utils
import time
import api
import sys
import os


BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


class Server:
    INBOUND_PORT = 54123
    #IV_KEY = base64.b64encode(get_random_bytes(16))
    IV_KEY = ''
    enciphered = False
    client_keys = {}

    def __init__(self, API, local):
        self.api = API
        self.IV_KEY = self.load_public_key(local)
        self.tic = time.time()
        self.client_ciphers = {}

    def load_public_key(self, ip):
        if os.path.isfile('public.key'):
            print '[*] Loading Public Server Key...'
            public_key = utils.swap('public.key', False).pop()
        else:
            public_key = self.api.create_public_keyfile(ip_address=ip)
        return public_key

    def add_client_key(self, client, key):
        self.client_keys[key] = client
        self.client_ciphers[client] = AES.new(base64.b64decode(key))
        self.enciphered = True
        return True

    def sys_cmd(self, client, cmd):
        os.system('%s >> cmd.txt' % cmd)
        output = utils.arr2lines(utils.swap('cmd.txt', True))
        try:
            client.send(output);    client.close()
        except socket.error:
            pass
        return output

    def shutdown(self):
        # Erase all keys
        rm_keys = 'ls *.api_key | while read n; do rm $n; done'
        os.system(rm_keys)


def start_listener(serve):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', serve.INBOUND_PORT))
        s.listen(5)
        print 'Listener Started on 0.0.0.0:%d' % serve.INBOUND_PORT
    except socket.error:
        return False
    return s


def listener(server_ip):

    # secrets = AES.new(serve.IV_KEY)
    API = api.API()
    serve = Server(API, server_ip)

    connections = []
    running = True
    tic = time.time()
    s = start_listener(serve)
    while running:
        if not s:
            time.sleep(5)
            s = start_listener(serve)
        try:
            ''' Accept a client '''
            client, addr = s.accept()
            client_ip = addr[0]
            connections.append(client_ip)

            ''' Receive a query '''
            query = client.recv(1024)
            print '[*] Connection accepted from %s [ Requesting %s ]' % (client_ip, query)

            if client_ip in API.clients:
                print '[*] %s has API Key' % client_ip
                client_cipher = AES.new(base64.b64decode(API.tokens[client_ip]))
                decoded_query = DecodeAES(client_cipher, query)
                print '[*] Decoded Query: %s' % decoded_query
                try:
                    command = decoded_query.split(' : ')[0]
                    request = decoded_query.split(' : ')[1]
                except IndexError:
                    pass
                if len(decoded_query.split(' : '))>1 and command in API.functions.keys():
                    print '[*] %s API Command Received from %s' % (command.upper(), client_ip)
                    result = API.functions[command](client, client_ip, request)


            elif query == '!?':
                client_key = API.create_public_keyfile(client_ip)
                client.send(client_key); client.close()
            else:
                print '[!!] Unauthorized Query'
                client.close()

        except KeyboardInterrupt:
            s.close()
            running = False
            pass
    ''' DELETE ALL KEYS ON SHUTDOWN '''
    serve.shutdown()
    s.close()
    print '[*] Server Killed [%ss Elapsed]' % str(time.time()-tic)


if __name__ == '__main__':
    listener(sys.argv[1])
