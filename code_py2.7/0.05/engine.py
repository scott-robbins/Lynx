# LYNX BACKEND - 3/27/2020 - S.Robbins
#
#
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


class StunServer:
    known = []

    clients = {'': []} # Keep Track of Clients who've connected
    public_key = ''
    uptime = 0.0
    inbound = 54123
    outbound = 32145

    def __init__(self, runtime):
        self.actions = {'GET_EXT_IP': self.relay_ext_ip}
        # Set up STUN Server Public/Private Keypairs
        self.public_key = self.load_keys()
        # Run the key distribution/NAT traversal server
        self.run_session_key_handler(runtime)

    def load_keys(self):
        if not os.path.isfile('stun_private.key'):
            key = utils.create_rsa_key('stun')
        else:
            key = utils.load_private_key('stun_private.pem')
        return key.publickey().exportKey()

    def key_exchange(self, client_socket, client_key):
        token = ''
        try:
            public_key_str = self.public_key
            client_socket.send(public_key_str)
            client_public_key_str = client_socket.recv(4096)

            cipher_rsa = PKCS1_OAEP.new(RSA.importKey(client_public_key_str))
            enc_key_str = cipher_rsa.encrypt(client_key)
            client_socket.send(enc_key_str)

            open('test', 'wb').write(client_public_key_str)
            token = utils.cmd('sha256sum test').pop().split(' ')[0]
            os.remove('test')
        except socket.error:
            print '[!!] Key Exchange FAILED'
            pass
        return client_socket, token

    def client_handler(self, client_socket, address):
        client_ip = address[0]
        client_port = str(address[1])
        '''    This is where the critical task of evaluating and responding (correctly)
             to clients and any/all of there queries will first occur. Keep it CLEAN and NEAT. '''

        if client_ip not in self.known:     # Initial Key Exchange
            client_id = base64.b64encode(get_random_bytes(32))
            client_socket, token = self.key_exchange(client_socket, client_id)
            self.clients[token] = [client_ip, client_port, client_id]
            self.known.append(client_ip)    # Add to known clients after key exchange
        else:
            raw_query = client_socket.recv(1028)
            client_token = raw_query.split('>>>>')[0]
            if client_token in self.clients.keys():
                client_id = self.clients[client_token][2]
            encrypted_query = raw_query.split('>>>>')[1]
            decrypted_query = utils.DecodeAES(AES.new(base64.b64decode(client_id)), encrypted_query)

            if decrypted_query.replace('\n','') in self.actions.keys():
                print '[*] Replying to %s query of %s' % (client_ip, decrypted_query)
                client_socket = self.actions[decrypted_query](client_socket, client_token)
            else:
                print '[!!] Uncrecognized Query:'
                print decrypted_query
        # Done processing the client request, regardless of what it was
        client_socket.close()

    def run_session_key_handler(self, timeout):
        t0 = time.time()
        date, local = utils.create_timestamp()
        print '[*] Server Started [%s - %s]' % (date, local)
        # Set up the STUN server socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', self.inbound))
        s.listen(5)
        # Run it for the given amount of time
        while (time.time() - t0) < timeout:
            try:
                # Accept incoming connections
                client, addr = s.accept()

                # Process the client's request (whatever it may be)
                worker = Thread(target=self.client_handler, args=(client, addr,))
                worker.daemon = True
                worker.start()

                # Logging clients that connect
                self.known = list(set(self.known))
            except socket.error:  # Obviously needs more precise error handling
                print '[!!] Connection Error'
                pass
        # Don't forget to close before leaving!
        print '[*] Shutting Down Server'
        s.close()

    def relay_ext_ip(self, client_socket, client_key):
        try:
            ip = self.clients[client_key][0]
            reply = 'The reply to your query is:\n%s' % ip
            client_socket.send(utils.EncodeAES(AES.new(base64.b64decode(client_key)), reply))
        except socket.error:
            print '[!!] Error Replying to Query'
            pass
        return client_socket


if __name__ == '__main__':
    # Run This for a few minutes to test the other end
    try:
        StunServer(500)
    except KeyboardInterrupt:
        pass

