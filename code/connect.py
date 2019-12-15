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

    def show_commands():
        syntax = ['sys_cmd', 'cmd_set', 'get_file', 'send_file']
        reply = '\t==== COMMAND_SET ====\n'
        for i in range(1,len(syntax)):
            reply += '[%d] %s\n' % (i, syntax[i])
        return reply

    actions = {'sys_cmd': os.system,
               'cmd_set': show_commands}

    inbound_port = 11235
    if not os.path.isfile('trusted_peers.txt'):
        os.system('touch trusted_peers.txt')

    k = security.get_keys()
    authenticated = False
    passwd = security.load_password()
    started = False
    queried = False
    query = ''

    while not started:
        started, s = create_listener(inbound_port)
        time.sleep(10)
    print '[*] Server Started'
    args = []
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
                client_key = client.recv(1024)
                print '[*] Received Client Key: %s' % client_key
                # cipher = AES.new(base64.b64decode(client_key))
                local_key = security.load_key()
                print '[*] Sending %s Encryption Key: %s' % (client_addr[0], base64.b64encode(local_key))
                client.send(base64.b64encode(local_key))

                ''' Receive Encrypted Query '''
                encrypted_query = client.recv(2048)
                print '[*] Received. Encrypted Query...'
                decrypted_query = security.DecodeAES(AES.new(local_key), encrypted_query)
                query = decrypted_query.split('Querying: ')[1].split('<')[0]
                try:
                    args = decrypted_query.split('~')[1:].replace('~', '')
                except IndexError:
                    pass
                print '[*] Decrypted Query: %s' % query
                if args:
                    print '[*] With Arguments: %s' % args
                queried = True
                client.close()
        except socket.error:
            print '[!!] Connection Error'
            s.close()
            running = False

    ''' Now Authenticated, So all outgoing communication are encrypted with local_key '''
    if queried:
        actions[query]()

    s.close()


if __name__ == '__main__':

    localhost = utils.get_lan_ip()

    if 'serve' in sys.argv:
        # try:
        serve()
        # except:
        #     print '[!!] Server Crashed [%ss elapsed]' % str(time.time() - tic)