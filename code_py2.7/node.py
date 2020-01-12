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
int_ip, ext_ip, nx_iface = engine.get_public_private_ip(verbose=False)


def verify_peer_list(e_ip, i_ip):
    '''   CHECK IF PEER_LIST ALREADY EXISTS  '''
    if os.path.isfile('peers.txt'):
        PEERS = {}
        peer_count = 0
        for line in utils.swap('peers.txt', False):
            try:
                eip = line.split(' : ')[0]
                iip = line.split(' : ')[1]
                PEERS[peer_count] = [eip, iip]
                peer_count += 1
            except IndexError:
                pass
        print '[*] %d Peers in Peer_List' % peer_count
    else:
        os.system('echo "%s : %s" >> peers.txt' % (e_ip, i_ip))
        return '%s : %s' % (e_ip, i_ip)
    return PEERS


def initialize_network(peers):
    '''         CREATE A CLIENT TO QUERY OTHER PEERS        '''
    live_peers = {}
    for peer_id, peer_info in peers.items():
        external = peer_info[0]
        internal = peer_info[1]
        print '[*] Contacting Peer %s' % external
        if int_ip != internal and ext_ip != external:
            success = False;
            reached = ''
            timeout = 10;
            tic = time.time();
            attempting = True
            while attempting and (time.time() - tic) < timeout:
                client.add_peer_cmd(internal)  # Make sure internal/external aren't a match first
                ext_key = internal.replace('.', '') + '.pem'
                if os.path.isfile(ext_key):
                    attempting = False
                    success = True;
                    reached = internal
                else:
                    timeout = 10;
                    tic = time.time();
                    attempting = True
                    print '[*] Retrying with %s' % external
                    while attempting and (time.time() - tic) < timeout:
                        client.add_peer_cmd(external)  # Make sure internal/external aren't a match first
                        attempting = False
                        success = True;
                        reached = external
        if success:
            # print '[*] SUCCESSFULLY CONTACTED PEER %s:%s' % (external, internal)
            live_peers[peer_id] = [reached, external, internal]
    print '[*] %d Peers Connected to Network' % (len(live_peers.keys()) + 1)  # count yourself
    '''     Distribute Current Peer List '''
    nx_times = {}
    for active in live_peers.keys():
        reachable, outer, inner = live_peers[active]
        ping_time = client.query_cmd(reachable, 'ping -c 1 1.1.1.1')
        try:
            dns_time = ping_time.split('time=')[1].split('\n')[0].split(' ')[0]
            nx_times[float(dns_time)] = active
        except IndexError:
            pass
    fastest_peer = live_peers[nx_times[min(nx_times.keys())]][0]
    print '[*] %s is the Fastest Peer' % fastest_peer
    return fastest_peer, live_peers


'''         INITIALIZE THE NETWORK                '''
initialize_network(verify_peer_list(ext_ip, int_ip))
