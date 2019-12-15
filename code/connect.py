from Crypto.Cipher import AES
import security
import random
import base64
import socket
import utils
import time
import sys
import os

tic = time.time()
DEBUG = True


def create_listener(port):
    s = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', port))
        s.listen(5)
    except socket.error:
        print '[!!] Unable to create socket'
        return False, s
    return True, s


def client_authentication(c, c_addr, pword):
    print '[*] Authenticating %s...' % c_addr[0]
    authentic = False
    cred_query = c.recv(1024)
    if DEBUG:
        print 'Query: %s' % cred_query
        print 'Login: %s' % pword
    try:
        key = cred_query.split('  :  ')[0]
        pss = cred_query.split('  :  ')[1].replace('\n', '')
        credentials = security.DecodeAES(AES.new(key), pss)
        if DEBUG:
            print 'Decrypted Query: %s' % credentials
        if credentials == pword:
            print '\033[1m\033[31m[*] %s \033[1mHas Successfully Authenticated\033[0m' % c_addr[0]
            c.send('[GOOD]')
            c.close()
            security.log_credentials(c_addr[0], credentials, key)
            authentic = True
        else:
            print '[!!] Authentication Failed for %s' % c_addr[0]
        c.close()
    except IndexError:
        print '[!!] Authentication Failed for %s' % c_addr[0]
        c.send('?')
        c.close()
    return authentic


def serve():
    inbound_port = 11235
    if not os.path.isfile('trusted_peers.txt'):
        os.system('touch trusted_peers.txt')

    k = security.get_keys()
    authenticated = False
    passwd = security.load_password()
    started = False

    while not started:
        started, s = create_listener(inbound_port)
        time.sleep(10)
    print '[*] Server Started'
    running = True
    while not authenticated and running:
        trusted = utils.swap('trusted_peers.txt', False)
        try:
            client, client_addr = s.accept()
            if client_addr[0] not in trusted:  # Authenticate client, and add to trusted peers
                authenticated = client_authentication(client, client_addr, passwd)
                client.close()
            else:       # KNOWN PEER
                print '[*] Known Peer %s connecting' % client_addr[0]
                client_key = base64.b64decode(client.recv(1024))
                cipher = AES.new(client_key)

                client.close()
        except socket.error:
            print '[!!] Connection Error'
            s.close()
            running = False
    s.close()


if __name__ == '__main__':

    localhost = utils.get_lan_ip()

    if 'serve' in sys.argv:
        # try:
        serve()
        # except:
        #     print '[!!] Server Crashed [%ss elapsed]' % str(time.time() - tic)