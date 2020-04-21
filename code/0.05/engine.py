import socket
import utils
import time
import sys
import os


class Hub:
    peer_pool = []
    hub_ext = ''
    hub_int = ''

    def __init__(self, mode):
        start_date, start_time = utils.create_timestamp()
        self.hub_ext = utils.get_ext_ip()
        self.hub_int = utils.get_int_ip()
        self.server_socket = utils.start_listener(mode['port'], mode['runtime'])
        print('[*] Server Created [%s  -  %s]' % (start_date, start_time))


    def shutdown(self):
        end_date, end_time = utils.create_timestamp()
        print('[*] Shutting Down [%s - %s]' % (end_date, end_time))

if __name__ == '__main__':
    hive = Hub({'port': 54123,
                'runtime': 3600
                })
