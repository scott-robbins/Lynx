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
        self.actions = {'show_peers': self.show_peers}

    def parse_request(self, raw_req):
        try:
            cid = raw_req.split('????')[0]
            raw_query = raw_req.split('????')[1]
            qA = raw_query.split('::::')[0]
            qB = raw_query.split('::::')[1]
        except IndexError:
            return False, '', ''
        return cid, qA, qB

    def client_handler(self, client_sock, client_addr):
        """ Client handler for engine """

        # Register new clients
        if client_addr not in self.known_peers:
            client_sock = self.add_client(client_sock, client_addr)
            client_sock.close()
            return
        # Handler (blocks!)
        raw_request = client_sock.recv(4096)

        try:
            # Process Request
            client_id, q, query = self.parse_request(raw_request)
            # Reply to the request
            if client_id not in self.clients.keys():
                client_sock.close()
            if client_id in self.clients.keys() and q in self.actions.keys():
                client_sock = self.actions[query](client_sock, client_id, query)
        except IndexError:
            print '[!!] Bad query from %s ' % str(client_addr[0])
            pass

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
            print '[*] %s has signed up as %s' % (addr, requested_uname)
            sock.send(token)
            self.known_peers.append(addr)
        else:
            sock.send('[!!] Username Taken')
        return sock

    def show_peers(self, sock, addr, request):
        clear_content = ''
        for peername in self.clients.keys():
            clear_content += '[*] User: %s\n' % peername
        sock.send(clear_content)    # TODO: Encrypt with session key
        return sock

