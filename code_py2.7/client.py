from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
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

default_port = 54123
lan_ip, ext_ip, nx_nic = engine.get_public_private_ip(verbose=True)
private_key = engine.load_private_key(ext_ip.replace('.','')+'.pem')
public_key = private_key.publickey()
DEBUG = True


def add_remote_host_public_key(remote_host, remote_key_file):
    session_key = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_host, default_port))
        s.send('&?Key')
        rmt_pub_key = s.recv(4096)
        open(remote_key_file, 'wb').write(rmt_pub_key)
        s.send(public_key.exportKey())
        session_key = base64.b64decode(s.recv(4096))
        open(remote_host.replace('.','')+'.token','wb').write(session_key)
        s.close()
    except socket.error:
        s.close()
        print '[!!] Connection Broken'
    return session_key


def get_file(remote_host, query):
    # Load Key
    tic = time.time()
    rmt_key = remote_host.replace('.', '') + '.pem'
    if not os.path.isfile(rmt_key):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (remote_host,
                                                                          remote_host)
        exit()
    rmt_pub_key = engine.load_private_key(rmt_key)
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(query)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)

    # Receive Reply and decrypt it
    reply = s.recv(65535)
    encrypted_key = reply.split('::::')[0]

    key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
    print '[*] Encryption Key: %s' % base64.b64encode(key)
    encrypted_data = reply.split('::::')[1]
    print '[*] Received %d pieces of encrypted data. Decrypting...' % len(encrypted_data)
    decrypted_data = utils.DecodeAES(AES.new(key), encrypted_data)
    if os.path.isfile(query):
        if raw_input('[!!] %s Already Exists, do you want to Overwrite it (y/n)?: '%query).upper() == 'Y':
            os.remove(query)
    resource = query.split(': ')[1]
    open(resource, 'wb').write(decrypted_data)
    print '[*] %d Bytes Transferred [%ss Elapsed]' % (os.path.getsize(resource),
                                                      str(time.time()-tic))


def put_file(remote_host, file_name):
    tic = time.time()
    rmt_key = remote_host.replace('.', '') + '.pem'
    if not os.path.isfile(rmt_key):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (remote_host,
                                                                          remote_host)
        exit()
    # Tell server the file we want to upload, and it's size
    rmt_pub_key = engine.load_private_key(rmt_key)
    statement = 'PUT_FILE : %s = %d' % (file_name, os.path.getsize(file_name))
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(statement)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)

    # Encrypt the file and send it
    raw_file_data = open(file_name, 'rb').read()
    key = get_random_bytes(32)
    encrypted_key = PKCS1_OAEP.new(rmt_pub_key).encrypt(key)
    encrypted_data = utils.EncodeAES(AES.new(key), raw_file_data)
    s.send(encrypted_key+';;;;'+encrypted_data)
    s.close()
    print '[*] Finished Sending %d bytes of Data to %s' % (os.path.getsize(file_name),
                                                           remote_host)


def query(remote_host, remote_key_file, cmd):
    if not os.path.isfile(remote_key_file):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (rmt, rmt)
        exit()
    # Load Key
    rmt_pub_key = engine.load_private_key(remote_host.replace('.', '') + '.pem')
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(cmd)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)
    print '[*] Query Sent to %s ' % remote_host

    # Receive Reply and decrypt it
    reply = s.recv(65535)
    key = PKCS1_OAEP.new(private_key).decrypt(reply.split('::::')[0])
    decrypted_data = utils.DecodeAES(AES.new(key), reply.split('::::')[1])
    print '[*] Reply:\n$ %s' % decrypted_data


if __name__ == '__main__':
    # client actions from the commandline below
    if 'add' in sys.argv and len(sys.argv) >= 3:
        rmt = sys.argv[2]
        r_key = rmt.replace('.', '') + '.pem'
        k = add_remote_host_public_key(rmt, r_key)
        open(rmt.replace('.', '') + '.token', 'wb').write(k)
        print '[*] Keys Exchanged With %s' % rmt

    if 'query' in sys.argv and len(sys.argv) >= 4:
        rmt = sys.argv[2]
        r_key = rmt.replace('.', '') + '.pem'
        q = utils.arr2str(sys.argv[3:])
        print '[*] Querying %s: %s' % (rmt, 'SYS_CMD : ' + q)
        query(rmt, r_key, 'SYS_CMD : ' + q)

    if 'get' in sys.argv and len(sys.argv) >= 4:
        remote = sys.argv[2]
        request = 'GET_FILE : ' + sys.argv[3]
        get_file(remote, request)

    if 'put' in sys.argv and len(sys.argv) >= 4:
        remote = sys.argv[2]
        local_file = sys.argv[3]
        if not os.path.isfile(local_file):
            print '[!!] Cannot Find %s' % local_file
        put_file(remote, local_file)
