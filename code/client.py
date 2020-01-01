from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
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

SESSION_KEY = base64.b64encode(get_random_bytes(16))


def connect(address, port):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((address, port))
        s.send('?')
        reply = s.recv(1024)
        s.close()
    except socket.error:
        pass
    return reply


def send(addr, port, msg):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((addr, port))
        s.send(msg)
        reply = s.recv(1024)
        s.close()
    except socket.error:
        s.close()
        pass
    return reply


if 'add' in sys.argv and len(sys.argv) >= 3:
    rmt = sys.argv[2]
    file_name = rmt.replace('.', '') + '.api_key'
    print '[*] Adding Peer %s' % rmt
    api_key = send(rmt,54123,'!?')
    print '[*] Receieved API Key: %s' % api_key
    open(file_name, 'wb').write(api_key)

'''       SEND A COMMAND    '''
if 'send' in sys.argv and len(sys.argv) >= 4:
    rmt = sys.argv[2]
    msg = utils.arr2str(sys.argv[3:])
    api_key_file = rmt.replace('.', '') + '.api_key'
    rmt_api_key = open(api_key_file, 'rb').read()
    cipher = AES.new(base64.b64decode(rmt_api_key))
    reply = send(rmt, 54123, EncodeAES(cipher, msg))
    print '[*] Received: %s' % DecodeAES(cipher, reply)

'''     GET A FILE      '''
if 'get' in sys.argv and len(sys.argv) >= 4:
    rmt = sys.argv[2]
    rmt_file = sys.argv[3]
    if len(rmt_file.split('/'))>1:
        local_file = rmt_file.split('/')[-1]
    else:
        local_file = rmt_file
    tic = time.time()
    print '[*] Fetching %s from %s'% (local_file, rmt)
    api_key_file = rmt.replace('.', '') + '.api_key'
    rmt_api_key = open(api_key_file, 'rb').read()
    cipher = AES.new(base64.b64decode(rmt_api_key))
    get_cmd = 'get_file : %s' % rmt_file
    reply = send(rmt, 54123, EncodeAES(cipher, get_cmd))
    if reply != 'Unable to Locate File!':
        if os.path.isfile(local_file):
            print '%s already exists.' % local_file
            if raw_input('Do you want to overwrite/delete existing file? (y/n):').upper() =='Y':
                open(local_file, 'wb').write(DecodeAES(cipher, reply))
        else:
            open(local_file, 'wb').write(DecodeAES(cipher, reply))
    print '[*] Finished Transferring %d Bytes [%ss Elapsed]' % (os.path.getsize(local_file),
                                                                str(time.time()-tic))

if 'put' in sys.argv and len(sys.argv) >= 4:
    rmt = sys.argv[2]
    local_file = sys.argv[3]
    if not os.path.isfile(local_file):
        print '[!!] Cannot Find %s ' % local_file
    else:
        print '[*] Sending %s' % local_file
        clear_text = open(local_file, 'rb').read()
        key = base64.b64decode(open(rmt.replace('.', '') + '.api_key','rb').read())
        cipher = AES.new(key)
        put_cmd = 'put_file : %s' % local_file
        encrypted_put = EncodeAES(cipher, put_cmd)
        encrypted_data = EncodeAES(cipher, open(local_file, 'rb').read())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print '[!!] Unable to create socket'
        try:
            s.connect((rmt, 54123))
            s.send(encrypted_put)
            max_file_size = int(DecodeAES(cipher,s.recv(1024)))
            print '[*] Recieved max file size: %dKb' % max_file_size
            print '[*] Sending Encrypted File [%dKb]' % int(os.path.getsize(local_file)/1000)
            s.send(encrypted_data)
            s.close()
        except socket.error:
            print '[!!] Connection Broken'
            s.close()