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


def request_api_key(client, ip_address, query, serve):
    k = base64.b64encode(get_random_bytes(16))
    key_out = query + '\n' + k
    key_file = ip_address[0].replace('.', '')+'.api_key'
    open(key_file, 'wb').write(key_out)
    try:
        client.send(key_out)
        client.close()
    except socket.error:
        print '[!!] Connection Error'
        pass
    return k


