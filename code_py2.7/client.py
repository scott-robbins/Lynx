from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
import multiprocessing
import base64
import socket
import engine
import utils
import time
import sys
import os

'''
Algorithm 	Sender uses: 	Receiver uses:
Encryption 	Public key 	    Private key
Signature 	Private key 	Public key
'''
# =========================== GLOBAL SETTINGS ============================= #
default_port = 54123
lan_ip, ext_ip, nx_nic = engine.get_public_private_ip(verbose=True)
private_key = engine.load_private_key(ext_ip.replace('.','-')+'.pem')
public_key = private_key.publickey()
DEBUG = False


# =========================== CLIENT FUNCTIONS ============================ #
def add_remote_host_public_key(remote_host, remote_key_file):
    session_key = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_host, default_port))
        s.send('&?Key')
        rmt_pub_key = s.recv(4096)
        open(remote_key_file, 'wb').write(rmt_pub_key)
        s.send(public_key.exportKey())
        session_key = base64.b64decode(s.recv(4096))
        open(remote_host.replace('.','')+'.token','wb').write(session_key)
        s.close()
    except socket.error:
        s.close()
        print '[!!] Connection Broken'
    return session_key


def get_file(remote_host, query):
    # Load Key
    tic = time.time()
    rmt_key = remote_host.replace('.', '-') + '.pem'
    if not os.path.isfile(rmt_key):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (remote_host,
                                                                          remote_host)
        exit()
    rmt_pub_key = engine.load_private_key(rmt_key)
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(query)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)

    ''' Introducing a Timeout in case no reply comes '''
    timeout = 30; success = False
    while not success or (time.time()-tic) < timeout:
        # Receive Reply and decrypt it
        reply = s.recv(120000)
        encrypted_key = reply.split('::::')[0]

        key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
        if DEBUG:
            print '[*] Encryption Key: %s' % base64.b64encode(key)
        encrypted_data = reply.split('::::')[1]
        if DEBUG:
            print '[*] Received %d pieces of encrypted data. Decrypting...' % len(encrypted_data)
        decrypted_data = utils.DecodeAES(AES.new(key), encrypted_data)
        if os.path.isfile(query):
            if raw_input('[!!] %s Already Exists, do you want to Overwrite it (y/n)?: ' % query).upper() == 'Y':
                os.remove(query)
        resource = query.split(':')[1].replace(' ', '')
        open(resource, 'wb').write(decrypted_data)
        print '[*] %d Bytes Transferred [%ss Elapsed]' % (os.path.getsize(resource),
                                                          str(time.time() - tic))
        s.close()
        success = True
    if not success:
        print '[!!] GetFile Timed Out'
        s.close()


def put_file(remote_host, file_name):

    rmt_key = remote_host.replace('.', '-') + '.pem'
    if not os.path.isfile(rmt_key):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (remote_host,
                                                                          remote_host)
        exit()
    # Tell server the file we want to upload, and it's size
    rmt_pub_key = engine.load_private_key(rmt_key)
    statement = 'PUT_FILE : %s = %d' % (file_name, os.path.getsize(file_name))
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(statement)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)

    ''' Introducing a Timeout in case no reply comes '''
    tic = time.time(); success = True
    while not success or (time.time() - tic) < 30:
        # Encrypt the file and send it
        raw_file_data = open(file_name, 'rb').read()
        key = get_random_bytes(32)
        encrypted_key = PKCS1_OAEP.new(rmt_pub_key).encrypt(key)
        encrypted_data = utils.EncodeAES(AES.new(key), raw_file_data)
        s.send(encrypted_key + ';;;;' + encrypted_data)
        s.close(); success = True
    if not success:
        print '[!!] PutFile Timed Out'
        s.close()
    if success and DEBUG:
        print '[*] Finished Sending %d bytes of Data to %s [%ss Elapsed]' % \
              (os.path.getsize(file_name), remote_host, str(time.time()-tic))


def get_share_file_list(remote_host):
    if not os.path.isfile(remote_host.replace('.', '-') + '.pem'):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (rmt, rmt)
        exit()
    # Load Key
    rmt_pub_key = engine.load_private_key(remote_host.replace('.', '-') + '.pem')
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt('SEE_SHARES : ""')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)
    encrypted_reply = s.recv(120000)
    session_key = encrypted_reply.split('::::')[0]
    encrypted_data = encrypted_reply.split('::::')[1]
    key = PKCS1_OAEP.new(private_key).decrypt(session_key)
    decrypted_data = utils.DecodeAES(AES.new(key), encrypted_data)
    print decrypted_data
    if decrypted_data != '':
        remote_shares = remote_host.replace('.', '')+'.shares'
        open(remote_shares, 'wb').write(decrypted_data)
    s.close()


def query(remote_host, remote_key_file, cmd):
    if not os.path.isfile(remote_key_file):
        print '[!!] No Public Key for %s. Run python client.py add %s' % (rmt, rmt)
        exit()
    # Load Key
    rmt_pub_key = engine.load_private_key(remote_host.replace('.', '-') + '.pem')
    encrypted_query = PKCS1_OAEP.new(rmt_pub_key).encrypt(cmd)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remote_host, 54123))
    s.send(encrypted_query)
    if DEBUG:
        print '[*] Query Sent to %s ' % remote_host

    # Receive Reply and decrypt it
    reply = s.recv(65535)  # OAEP should help against plaintext attacks on RSA key
    key = PKCS1_OAEP.new(private_key).decrypt(reply.split('::::')[0])
    decrypted_data = utils.DecodeAES(AES.new(key), reply.split('::::')[1])
    s.close()
    return decrypted_data


def add_peer_cmd(rem):
    r_k = rem.replace('.', '-') + '.pem'
    k = add_remote_host_public_key(rem, r_k)
    if DEBUG:
        print '[*] Keys Exchanged With %s' % rem
    open(rem.replace('.', '') + '.token', 'wb').write(k)


def query_cmd(rem, q):
    r_key = rem.replace('.', '-') + '.pem'
    if DEBUG:
        print '[*] Querying %s: %s' % (rem, 'SYS_CMD : ' + q)
    return query(rem, r_key, 'SYS_CMD : ' + q)


def get_file_req(rem, resource):
    request = 'GET_FILE : ' + resource
    get_file(rem, request)


def put_file_req(rem, local):
    if not os.path.isfile(local):
        print '[!!] Cannot Find %s' % local
    put_file(rem, local)
    return True


def check_peer_connections(node_a, node_b):
    PEERS = {node_a: [], node_b: []}
    rkey_a = node_a.replace('.', '-') + '.pem'
    rkey_b = node_b.replace('.', '-') + '.pem'
    keys = utils.cmd('ls *pem')
    if rkey_a not in keys:
        print '[*] Adding Peer %s' % node_a
        os.system('python client.py add %s >> /dev/null 2>&1' % node_a)
        if os.path.isfile(rkey_a):  # TODO: Make sure this doesnt timeout
            routed, latency = engine.parse_ping(query_cmd(node_a, 'ping -c 1 %s' % node_b))
            if routed:
                PEERS[node_a].append(node_b)
    else:
        routed, latency = engine.parse_ping(query_cmd(node_a, 'ping -c 1 %s' % node_b))
        if routed:
            PEERS[node_a].append(node_b)

    if rkey_b not in keys:
        print '[*] Adding Peer %s' % node_b
        os.system('python client.py add %s >> /dev/null 2>&1' % node_b)
        if os.path.isfile(rkey_b):
            routed, latency = engine.parse_ping(query_cmd(node_b, 'ping -c 1 %s' % node_a))
            if routed:
                PEERS[node_b].append(node_a)
    else:
        routed, latency = engine.parse_ping(query_cmd(node_b, 'ping -c 1 %s' % node_a))
        if routed:
            PEERS[node_b].append(node_a)
    return PEERS


def check_npeer_connections(nodes):
    PEERS = {}
    for n in nodes:
        PEERS[n] = []
    for a in nodes:
        for b in nodes:
            if a != b:
                if b not in PEERS[a]:
                    p2p = check_peer_connections(a, b)
                    for node in p2p.keys():
                        for peer in p2p[node]:
                            PEERS[peer].append(node)
    # Remove duplicates (a connection is two sided
    for dev in PEERS.keys():
        PEERS[dev] = list(set(PEERS[dev]))
    return PEERS


def create_manifest():
    tic = time.time()
    shared, file_hashes = engine.crawl_dir('SHARED', verbose=False)
    header = '[*] %d Files in Shared Folder\n' % len(shared['file'])
    for f, h in file_hashes.iteritems():
        header += '%s = %s\n' % (f, h)
    open('shared_manifest.txt', 'wb').write(header)
    print '[*] Finished Logging %d Files [%ss Elapsed]' % (len(file_hashes.keys()),
                                                           str(time.time()-tic))


def file_sync():
    if not os.path.isfile('shared_manifest.txt'):
        create_manifest()
    file_data = engine.parse_manifest_file('shared_manifest.txt')
    manifest_hash = engine.get_sha256_sum('shared_manifest.txt', verbose=False)
    shared_files = file_data.keys()

    if os.path.isfile('peers.txt') and os.path.isfile('peers.key'):
        utils.decrypt_file('peers.txt', 'clear_peer.txt', True)
        for line in utils.swap('clear_peer.txt', True):
            remote = line.replace('-', '.').replace(' ', '')
            if remote != ext_ip and remote != lan_ip:
                if os.path.isfile(remote.replace('.', '') + '.shares'):
                    os.remove(remote.replace('.', '') + '.shares')
                time.sleep(0.1)  # Requests are being made to fast to catch replies

                get_share_file_list(remote)
                try:
                    remote_shares = utils.swap(remote.replace('.', '') + '.shares', False)
                    # Get remote file if its not in local share file
                    for ln in remote_shares:
                        try:
                            name = ln.split(' = ')[0]
                            checksum = ln.split(' = ')[1]
                            if name not in shared_files:
                                get_file(remote, 'GET_FILE : %s' % name)
                                if utils.get_sha256_sum(name, False) != checksum:
                                    print '[!!] %s FILE HASH DOES NOT MACH' % name
                                    os.remove(name)
                        except IndexError:
                            print '[!!] Error Getting: %s:%s' % (remote, name)
                            pass
                    # Now put local files onto remote if they dont have them
                    for f in shared_files:
                        if f not in remote_shares:
                            print '[*] Sending %s to %s' % (f, remote)
                            time.sleep(0.1)  # Requests are being made to fast to catch replies
                            put_file(remote, f)
                except IOError:
                    print '[!] %s has no Shared Files' % remote


# ===========================       MAIN       ============================ #
if __name__ == '__main__':
    # client actions from the commandline below
    if 'add' in sys.argv and len(sys.argv) >= 3:
        rmt = sys.argv[2]
        r_key = rmt.replace('.', '-') + '.pem'
        k = add_remote_host_public_key(rmt, r_key)
        open(rmt.replace('.', '') + '.token', 'wb').write(k)
        print '[*] Keys Exchanged With %s' % rmt

    if 'query' in sys.argv and len(sys.argv) >= 4:
        rmt = sys.argv[2]
        r_key = rmt.replace('.', '-') + '.pem'
        q = utils.arr2str(sys.argv[3:])
        print '[*] Querying %s: %s' % (rmt, 'SYS_CMD : ' + q)
        print query(rmt, r_key, 'SYS_CMD : ' + q)

    if 'get' in sys.argv and len(sys.argv) >= 4:
        remote = sys.argv[2]
        request = 'GET_FILE : ' + sys.argv[3]
        get_file(remote, request)

    if 'show' in sys.argv and len(sys.argv) >= 3:
        remote = sys.argv[2]
        get_share_file_list(remote)

    if 'put' in sys.argv and len(sys.argv) >= 4:
        remote = sys.argv[2]
        local_file = sys.argv[3]
        if not os.path.isfile(local_file):
            print '[!!] Cannot Find %s' % local_file
        put_file(remote, local_file)

    if 'log' in sys.argv:
        engine.log_known_peers(DEBUG)

    if '?NAT' in sys.argv and len(sys.argv)<=3:
        node_a = raw_input('Enter Server_A IP Address: ')
        node_b = raw_input('Enter Server_B IP Address: ')
        print engine.check_peer_connections(node_a, node_b)

    if '?NAT' in sys.argv and len(sys.argv) == 4:
        node_a = sys.argv[2]
        node_b = sys.argv[3]
        connectivity = check_peer_connections(node_a, node_b)
        print connectivity

    if '?NAT' in sys.argv and len(sys.argv) > 4:
        tic = time.time()
        machines = sys.argv[2:]
        connectivity = check_npeer_connections(machines)
        print connectivity
        print '[*] FINISHED [%ss Elapsed]' % str(time.time()-tic)

    if 'sync' in sys.argv:
        file_sync()


# EOF
