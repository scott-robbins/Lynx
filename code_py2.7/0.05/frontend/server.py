# LYNX FRONTEND - 3/27/2020 - S.Robbins
# This is the bulk of the code which acts as basic HTTP Server.
# Pages are served to clients with some locally stored files,
# and some pages which are generated on the fly (dynamic pages).
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from multiprocessing import Process
import base64
import socket
import utils
import time
import sys
import os


def create_listener(timeout):
    created = False
    while not created:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', 80))
            s.listen(5)
            created = True
        except socket.error:
            print '[!!] Error Creating Listener...'
            os.system('sh ./kill_listeners.sh >> /dev/null 2>&1')
            time.sleep(timeout)
    print '[*] Listener Started'
    return s


def client_handler(serve, sock, peers, active):
    success = False

    try:    # Handle Client Connection
        client, client_addr = sock.accept()
        ip = client_addr[0]
        print '[*] %s has connected' % client_addr[0]
        # Check if client is a known peer or active
        if ip not in list(set(peers)):
            new_client = True
        else:
            new_client = False
        # Receive a request
        t0 = time.time(); recvd = False
        try:
            while not recvd and (time.time() - t0) < 3:
                request = client.recv(2048)
                recvd = True
        except socket.error:
            client.close
            print '[!!] %s has exceeded patience [3s TTL]' % ip
            return success
        # Handle Client Request
        query = request.split('\r\n')



        client.close()
    except socket.error:
        print '[*] %s disconnected unexpectedly' % client_addr[0]
        client.close()
        success = False
    return success


def run(n_threads):
    runtime = 3600 * 72
    # Start Http Server
    server = HttpServer()
    clients = []
    active_clients = {}
    running = True

    # Create Listener
    handler = create_listener(15)
    # worker = multiprocessing.Pool(processes=n_threads)
    # Start accepting requests
    try:
        while running and (time.time() - server.tic) < runtime:
            server_thread = Process(target=client_handler, args=(server,
                                                                 handler,
                                                                 clients,
                                                                 active_clients))
            server_thread.start()
            server_thread.join()

    except KeyboardInterrupt:
        handler.close()
        print '\033[1m[!!]\033[31m Server Killed\033[0m'
        # TODO: Graceful shutdown
        exit()


class HttpServer:
    tic = 0
    known = {}

    def __init__(self):
        self.tic = time.time()
        self.actions = {}
        self.add_shared_files()

    def add_shared_files(self):
        if not os.path.isdir('../SHARED/Downloadable'):
            if os.path.isdir('../SHARED'):
                os.system('mkdir ../SHARED/Downloadable')
            else:
                os.system('mkdir ../SHARED')
                os.system('mkdir ../SHARED/Downloadable')
            return
        for name in os.listdir('../SHARED/Downloadable'):
            query_string = 'GET /HARED/Downloadable/%s HTTP/1.1' % name
            self.actions[query_string] = self.file_download

    def file_download(self, c, f, q, ci):
        if ci[0] in self.known:
            file_name = q.split('HTTP/1.1')[0].split('GET')[1].replace(' ', '')
            print '[*] %s is downloading %s' % (ci[0], file_name)
            if os.path.isfile('..' + file_name):
                c.send(open('..' + file_name, 'rb').read())
            d, l = utils.create_timestamp()
            # maintain state with a file for this client, encrypted w their public key
            state_file = self.known[ci[0]] + '.state'
            if not os.path.isfile(state_file):
                open(state_file, 'wb').write('%s logged in from %s [%s -%s]\n' % (self.known[ci[0]], ci[0], d, l))
            open(state_file, 'a').write('%s [%s] is downloading %s\nUserAgent:\n%s\n' %
                                        (self.known[ci[0]], ci[0], file_name.split('/')[-1], self.get_user_agent(f)))
        else:
            forbidden = open('assets/forbidden.html', 'rb').read()
            c.send(forbidden)
        return c


if __name__ == '__main__':
    # Create LogFile
    date, localtime = utils.create_timestamp()
    log_file_name = date.replace('/', '') + '_' +\
                    localtime.split(':')[0]+localtime.split(':')[1] + '.log'
    open(log_file_name, 'wb').write('[*] Server Started %s -%s\n====================' % (date, localtime))

    # TODO: Load Known Users

    # Start Server
    run(n_threads=3)

    # Shutdown
    print '[!!] Shutting Down Server...'