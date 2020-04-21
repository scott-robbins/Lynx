import socket
import utils
import time
import sys
import os


class P2PHandler:

    known_peers = []

    def __init__(self):
        self.actions = {}

    def client_handler(self, client_sock, client_addr):
        if client_addr not in self.known_peers:
            self.known_peers.append(client_addr)
        # TODO: Write the handler!

        # Close socket when finished!!
        client_sock.close()

