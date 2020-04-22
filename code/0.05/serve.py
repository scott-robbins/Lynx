from Crypto.Random import get_random_bytes
import base64
import socket
import utils
import time
import sys


class P2PHandler:
    clients = {}
    known_peers = []

    def __init__(self):
        self.actions = {'echo'}

    def client_handler(self, client_sock, client_addr):
        """ Client handler for engine """
        # Register new clients
        if client_addr not in self.known_peers:
            client_sock = self.add_client(client_sock, client_addr)
            client_sock.close()
            return
        # Handler (blocks!)
        raw_request = client_sock.recv(4096)

        # Process Request
        client_id = raw_request.split('????')[0]
        raw_query = raw_request.split('????')[1]
        q = raw_query.split('::::')[0]
        query = raw_query.split('::::')[1]

        # Reply to the request
        if client_id not in self.clients.keys():
            client_sock.close()
        if client_id in self.clients.keys() and q in self.actions.keys():
            client_sock = self.actions[query](client_sock, client_id, query)

        # Close socket when finished!!
        client_sock.close()

    def add_client(self, sock, addr):
        # Assign unique token
        token = base64.b64encode(get_random_bytes(24))
        recvd = False
        ti = time.time()
        while not recvd and (time.time() - ti) < 3:
            requested_uname = sock.recv(512)
            recvd = True
        # Make Sure the name isn't already taken
        if requested_uname not in self.clients.keys():
            self.clients[requested_uname] = token
            sock.send(token)
            self.known_peers.append(addr)
        else:
            sock.send('[!!] Username Taken')
        return sock

    # TODO: Test method for development only!!
    def echo(self, c, id, q):
        try:
            c.send(q)
        except socket.error:
            pass
        return c

