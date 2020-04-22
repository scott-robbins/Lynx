from threading import Thread
import socket
import serve
import utils
import time
import sys
import os


class Hub:
    peer_pool = []
    hub_ext = ''
    hub_int = ''
    running = False

    def __init__(self, mode):
        start_date, start_time = utils.create_timestamp()
        self.hub_ext = utils.get_ext_ip()
        self.hub_int = utils.get_int_ip()
        self.server_socket = utils.start_listener(mode['port'], mode['ttl'])
        print('[*] Server Created [%s  -  %s]' % (start_date, start_time))
        try:
            self.run(mode)
        except KeyboardInterrupt:
            pass
        # Shutdown the server when finished
        self.shutdown()

    def run(self, m):
        self.running = True
        tic = time.time()
        handler = serve.P2PHandler()
        while self.running and (time.time()-tic) < m['runtime']:
            '''     SERVING     '''
            client_socket, client = self.server_socket.accept()
            worker = Thread(target=handler.client_handler, args=(client_socket, client[0]))
            worker.daemon = True
            worker.start()
            worker.join()
        return

    def shutdown(self):
        """ Shutdown the server """
        end_date, end_time = utils.create_timestamp()
        print('[*] Shutting Down [%s - %s]' % (end_date, end_time))
        try:
            self.server_socket.close()
            success = True
        except socket.error:
            success = False
            print('[!!] Error Shutting Down Server')
        return success


if __name__ == '__main__':
    hive = Hub({'port': 54123,
                'runtime': 3600,
                'ttl': 10})
