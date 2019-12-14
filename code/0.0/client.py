from Crypto.Hash import SHA256
import random
import base64
import socket
import utils
import time
import sys
import os


def calculate_token(remote_public_key, verbose):
    rmt_head64 = utils.arr2str(list(remote_public_key.split('\n')[1:8]))
    rmt_token = SHA256.new(rmt_head64).hexdigest()[0:32]
    if verbose:
        print '[*] Token Calculated: %s' % rmt_token
    return rmt_token


def query(ip_addr, rmt_port, question):
    reply = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_addr, rmt_port))
        s.send(question)
        reply = s.recv(65000)
    except socket.error:
        print '[!!] Connection Error... Query Failed!'
        s.close()
    return reply, s


local_ip = utils.get_local_ip()
peer_keys = {}

if len(sys.argv) > 2 and 'test' in sys.argv:
    ip = sys.argv[2]
    port = int(sys.argv[3])
    ''' First Get the Remote Servers Public key to be used going forward '''
    rmt_pbk, s = query(ip, port, '?')
    if rmt_pbk and os.path.isfile('KEYS/public.pem'):
        pbk = open('KEYS/public.pem', 'rb').read()
        s.send(pbk)
    elif rmt_pbk:
        public_key = utils.create_ephemeral_key()
        head64 = utils.arr2str(list(public_key.exportKey().split('\n')[1:8]))
        token = SHA256.new(head64).hexdigest()[0:32]
        s.send(public_key.exportKey())
        print token
    s.close(); print 'Key Exchange Complete!'
    new_port = int(raw_input('enter new_port: '))

    ''' Now try making a simple query (asking how many files are in Shared/ folder) '''
    rmt_token = calculate_token(remote_public_key=rmt_pbk, verbose=True)
    # new_port = int(raw_input('Enter New Port: '))
    files, srvr = query(ip, new_port, '?'+rmt_token)
    print '[*] %s' % files
    srvr.close()
    new_port = int(raw_input('enter new_port: '))

    ''' Attempt to download a file from the remote server '''
    # new_port = int(raw_input('Enter New Port: '))
    print 'Testing File Download...'
    file_data, c = query(ip, new_port,'?'+rmt_token+': test.txt')
    open('test.txt', 'w').write(file_data); c.close()
    if os.path.getsize('test.txt') > 0:
        print '[*] File Download Finished: test.txt %d bytes' % os.path.getsize('test.txt')
        os.system('sha256sum test.txt')
    c.close()
    new_port = int(raw_input('enter new_port: '))

    ''' Attempt to upload a file to the remote server '''
    if os.path.isfile('test_up.txt'):
        os.remove('test_up.txt')
    print 'Testing File Upload...'      # Create a random test file
    random_content = ''
    for i in range(10):
        for j in range(10):
            random_content += utils.arr2str(random.sample(utils.charfeed, 26))+'\n'
        # random_content += '\n'
    open('test_up.txt', 'w').write(random_content)
    # new_port = int(raw_input('Enter New Port: '))
    print '[*] Sending %d bytes ' % os.path.getsize('test_up.txt')
    os.system('sha256sum test_up.txt')
    pipe_size, p = query(ip, new_port, '!' + rmt_token + ': test_up.txt 2600')
    p.send(random_content)
    print '[*] File Uploaded'
