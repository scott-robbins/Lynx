from Crypto.Cipher import AES
import security
import base64
import socket
import utils
import time
import sys
import os

tic = time.time()

def create_listener(port):
    s = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', port))
        s.listen(5)
    except socket.error:
        print '[!!] Unable to create socket'
    return s


def serve():
    if not os.path.isfile('trusted_peers.txt'):
        os.system('touch trusted_peers.txt')
    inbound_port = 11235
    k = security.get_keys()
    authenticated = False
    passwd = security.load_password()
    s = create_listener(inbound_port)
    while not authenticated:
        trusted = utils.swap('trusted_peers.txt', False)
        try:
            client, client_addr = s.accept()
            if client_addr[0] not in trusted:   #  Authenticate client, and add to trusted peers
                print '[*] Authenticating %s...' % client_addr[0]
                cred_query = client.recv(1024)
                try:
                    key = cred_query.split('  :  ')[0]
                    pss = cred_query.split('  :  ')[1].replace('\n', '')
                    credentials = security.DecodeAES(AES.new(key), pss)
                    if credentials == passwd:
                        authenticated = True
                        print '\033[1m\033[31m[*] %s \033[1mHas Successfully Authenticated\033[0m' % client_addr[0]
                        client.send('[GOOD]')
                        client.close()
                        open('trusted_peers.txt', 'wb').write(client_addr[0])
                        # TODO: Get Remote clients keys and write those, then use trusted_peers
                        #  To be able to associate that with the remote peer for easier setup
                    else:
                        print '[!!] Authentication Failed for %s' % client_addr[0]
                    client.close()
                except IndexError:
                    print '[!!] Authentication Failed for %s' % client_addr[0]
                    client.send('?')
                    client.close()

        except socket.error:
            print '[!!] Connection Error'
            s.close()
            authenticated = True
    s.close()


if __name__ == '__main__':
    if 'serve' in sys.argv:
        try:
            serve()
        except:
            print '[!!] Server Crashed [%ss elapsed]' % str(time.time() - tic)