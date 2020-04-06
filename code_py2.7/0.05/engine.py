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

    clients = {'127.0.0.1': [-1]} # Keep Track of Clients who've connected
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

    # TODO: Determine if self is public routable or behind nat?
    def client_handler(self, client_socket, address):
        ip = address[0]
        port = str(address[1])
        # Keep Track Of who is connecting, and assign session Keys if first time
        if ip not in self.known:
            client_socket.send(self.public_key)
            client_public_key = RSA.importKey(client_socket.recv(4096))

            print '[*] Public Key received from %s' % ip        # Only for debugging
            # Negotiation - Only use PKI to encrypt key for AES
            iv = base64.b64encode(get_random_bytes(24))
            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            enc_session_key = cipher_rsa.encrypt(iv)
            client_socket.send(enc_session_key)
            self.clients[client_public_key.exportKey()] = [ip, port, iv]
            self.known.append(ip)
            print '[*] Encrypted Session Key sent to %s' % ip   # Only for debugging
        else: # If recognized, use the session key already associated with client
            try:
                client_public_key = RSA.importKey(client_socket.recv(4096))
                key_str = client_public_key.exportKey()
                client_ip = ip
                if key_str in self.clients.keys():
                    print '[*] Client %s Is Making a query' % client_ip
                    dec_key = base64.b64decode(self.clients[key_str][2])
                else:
                    print '[!!] Known client %s is presenting Uncrecognized Key %s' %\
                          (ip, client_public_key)
                # Decrypt the query (encrypted with clients private key) with an AES instance that is
                # initialized using a negotiated
                encrypted_query = client_socket.recv(4096)
                decrypted_query = utils.DecodeAES(AES.new(dec_key), encrypted_query)
                print '[*] Received Query from %s' % client_ip
                print decrypted_query
                # Reply to query if necessary
                if decrypted_query in self.actions.keys():
                    client_socket = self.actions[decrypted_query](client_socket, client_public_key)
            except socket.error:
                pass

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
            [ip, port, iv] = self.clients[client_key]
            reply = 'The reply to your query is:\n%s' % ip
            client_socket.send(utils.EncodeAES(AES.new(base64.b64decode(iv)),reply))
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

