from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import random
import engine
import socket
import utils
import time
import sys
import os


BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


class API:
    tokens = {}
    clients = []

    def __init__(self):
        self.tic = time.time()
        self.functions = {'sys_cmd': self.sys_cmd,
                          'show_files': self.show_files}

    def request_api_key(self, client, ip_address, query):
        k = base64.b64encode(get_random_bytes(16))
        key_out = query + '\n' + k
        key_file = ip_address[0].replace('.', '') + '.api_key'
        open(key_file, 'wb').write(key_out)
        self.clients.append(ip_address)
        try:
            client.send(key_out)
            client.close()
        except socket.error:
            print '[!!] Connection Error'
            pass
        return k

    def create_public_keyfile(self, ip_address):
        k = base64.b64encode(get_random_bytes(16))
        key_file = ip_address.replace('.', '') + '.api_key'
        if os.path.isfile(key_file):
            print '[!!] %s Already Exists' % key_file
            return utils.swap(key_file,False).pop()
        else:
            open(key_file, 'wb').write(k)
            self.clients.append(ip_address)
            self.tokens[ip_address] = k
            return k

    def create_cipher(self, ip):
        key = base64.b64decode(self.tokens[ip])
        return AES.new(key)

    def show_files(self, client, ip_address, query):
        cipher = self.create_cipher(ip_address)
        content = ''
        local_files = utils.cmd('ls')
        for file_name in local_files:
            content += file_name + '\n'
        encrypted_content = EncodeAES(cipher, content)
        client.send(encrypted_content)
        client.close()

    def sys_cmd(self, client, ip_address, query):
        cipher = self.create_cipher(ip_address)
        result = utils.cmd(query)
        if len(result) > 1:
            content = utils.arr2lines(result)
        else:
            content = utils.arr2str(result)
        encrypted_content = EncodeAES(cipher, content)
        client.send(encrypted_content)
        client.close()

        return result

# def list_local_files(client, ip_address, query, serve):

