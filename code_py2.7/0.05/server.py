# LYNX FRONTEND - 3/27/2020 - S.Robbins
# This is the bulk of the code which acts as basic HTTP Server.
# Pages are served to clients with some locally stored files,
# and some pages which are generated on the fly (dynamic pages).
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
'''
>>> from threading import Thread
>>> import socket
>>> def work(conn):
...   while True:
...     msg = conn.recv(1024)
...     conn.send(msg)
...
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
>>> sock.bind(('localhost', 5566))
>>> sock.listen(5)
>>> while True:
...   conn,addr = sock.accept()
...   t=Thread(target=work, args=(conn,))
...   t.daemon=True
...   t.start()
'''


if __name__ == '__main__':
    # Create LogFile
    date, ltime = utils.create_timestamp()
    log_file_name = date.replace('/', '') + '_' + ltime.split(':')[0]+ltime.split(':')[1] + '.log'
    open(log_file_name, 'wb').write('[*] Server Started %s -%s\n====================' % (date, ltime))

    # TODO: Load Known Users

    # Shutdown
    print '[!!] Shutting Down Server...'
