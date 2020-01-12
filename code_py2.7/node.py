from threading import Thread
import handler
import engine
import client
import utils
import time
import sys
import os

'''   START A HANDLER TO LISTEN FOR INBOUND CONNECTIONS '''
listener = Thread(target=handler.Serve, args=('listener',))
listener.setDaemon(True)
listener.start()
# listener = handler.Serve(mode='listener')

'''   CHECK IF PEER_LIST ALREADY EXISTS  '''
if os.path.isfile('peers.txt'):
    PEERS = {}
    peer_count = 0
    for line in utils.swap('peers.txt', False):
        try:
            ext_ip = line.split(' : ')[0]
            int_ip = line.split(' : ')[1]
            PEERS[peer_count] = [ext_ip, int_ip]
            peer_count += 1
        except IndexError:
            pass
    print '[*] %d Peers in Peer_List' % peer_count

'''         CREATE A CLIENT TO QUERY OTHER PEERS        '''
for peer_id, peer_info in PEERS.items():
    external = peer_info[0]
    internal = peer_info[1]
    print '[*] Contacting Peer %s' % external
    # Make sure internal/external dont match self first
    client.add_peer(external)

try:
    listener.join()
except KeyboardInterrupt:
    print '[!!] KILLED'
    exit()
    os.system('ps aux | grep "python node.py" | cut -d ' ' -f 2 | while read n; do kill -9 $n; done')
