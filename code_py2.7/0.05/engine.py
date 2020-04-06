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
    actions = {'GET_EXT_IP'}
    clients = {'127.0.0.1': [-1]} # Keep Track of Clients who've connected
    public_key = ''
    uptime = 0.0
    inbound = 54123
    outbound = 32145

    def __init__(self, runtime):
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
        # TODO: Keep Track Of who is connecting, and assign session Keys if first time
        #  If recognized, use the session key saved already. If recognized and no session
        #  Key is present, then something is wrong (possible security issue)
        client_file = ip + ':' + port
        if client_file not in self.clients.keys():
            client_socket.send(self.public_key)
            client_public_key = RSA.importKey(client_socket.recv(4096))
            # open(client_file, 'wb').write(client_public_key)

            print '[*] Public Key received from %s' % ip        # Only for debugging
            # Negotiation - Only use PKI to encrypt key for AES
            iv = base64.b64encode(get_random_bytes(32))
            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            enc_session_key = cipher_rsa.encrypt(iv)
            client_socket.send(enc_session_key)
            self.clients[client_public_key.exportKey()] = [ip, port, iv]
            print '[*] Encrypted Session Key sent to %s' % ip   # Only for debugging
        else:
            try:
                client_public_key = RSA.importKey(client_socket.recv(4096))
                client_addr = self.clients[client_public_key.exportKey()]
                client_ip = client_addr[0]
                client_port = client_addr[1]
                dec_key = base64.b64decode(client_addr[2])
                # Decrypt the query (encrypted with clients private key) with an AES instance that is
                # initialized using a negotiated
                encrypted_query = client_socket.recv(4096)
                decrypted_query = utils.DecodeAES(AES.new(dec_key), encrypted_query)
                print '[*] Received Query %s from %s' % (decrypted_query, client_ip)
                # Reply to query if necessary

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
                self.known.append(addr[0])

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


if __name__ == '__main__':
    # Run This for a few minutes to test the other end
    try:
        StunServer(500)
    except KeyboardInterrupt:
        pass

