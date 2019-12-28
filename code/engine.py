from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import random
import utils
import time
import api
import os


BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


class Server:
    INBOUND_PORT = 54123
    IV_KEY = base64.b64encode(get_random_bytes(16))
    enciphered = False
    client_keys = {}

    def __init__(self):
        self.tic = time.time()
        self.client_ciphers = {}
        self.client_keys['?'] = self.list_commands
        self.client_keys['!'] = self.sys_cmd

    def sys_cmd(self, client, cmd):
        os.system('%s >> cmd.txt' % cmd)
        output = utils.arr2lines(utils.swap('cmd.txt', True))
        try:
            client.send(output)
            client.close()
        except socket.error:
            pass
        return output

    def add_client_key(self, client, key):
        self.client_keys[key] = client
        self.client_ciphers[client] = AES.new(base64.b64decode(key))
        self.enciphered = True

    def list_commands(self, client, query):
        cmd_list = ''
        for cmd in self.client_keys.keys():
            cmd_list += cmd + '\n'
        try:
            client.send(cmd_list)
            client.close()
        except socket.error:
            print '[!!] Connection Error'
            pass
        return cmd_list

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


def give_key(s, addr, q, serve):
    given = False
    try:
        s.send(serve.IV_KEY)
        s.close()
        given = True
    except socket.error:
        print '[!!] Connection Error'
        pass
    return given


def listener():
    serve = Server()
    # secrets = AES.new(serve.IV_KEY)

    actions = {'?': give_key,
               serve.IV_KEY: api.request_api_key
               }
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
            connections.append(addr[0])

            ''' Receive a query '''
            query = client.recv(1024)
            print '[*] Connection accepted from %s is requesting %s' % (addr[0], query)
            if query in actions.keys():
                reply = actions[query](client, addr, query, serve)
                if query == serve.IV_KEY:
                    print '[**] Client Key Added'
                    serve.add_client_key(addr[0], reply)
            elif serve.enciphered:
                print '[*] Decrypting query'
                client_cipher = serve.client_ciphers[addr[0]]
                decrypted_query = DecodeAES(client_cipher, query)
                if decrypted_query in serve.client_keys:
                    if '!' in decrypted_query.split('::'):
                        query = utils.arr2str(decrypted_query.split('::')[1:])
                    print serve.client_keys[decrypted_query](client, query)
                    serve.client_keys[decrypted_query](client, query)
                elif '!' in decrypted_query.split('::'):
                    query = utils.arr2str(decrypted_query.split(':: ')[1:])
                    print '[*] Executing sys_cmd: %s' % query
                    serve.client_keys['!'](client, query)
        except KeyboardInterrupt:
            s.close()
            running = False
            pass
    serve.shutdown()
    s.close()
    print '[*] Server Killed [%ss Elapsed]' % str(time.time()-tic)


if __name__ == '__main__':
    listener()
