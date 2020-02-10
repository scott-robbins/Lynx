from Crypto.Cipher import AES
import base64
import socket
import utils
import time
import sys
import os


def refresh_registered_nodes():
    if not os.path.isfile('registered.txt'):
        return
    nodes = {}
    unames = []
    creds = {}
    for line in utils.swap('registered.txt', False):
        try:
            user = line.split('@')[0]
            ip   = line.split('@')[1].split('=')[0]
            creds[user] = line.split('=')[1]
            unames.append(user)
            nodes[user] = ip
        except IndexError:
            pass

    os.remove('registered.txt')
    content = ''
    for n in nodes.keys():
        content += '%s@%s=%s\n' % (n,nodes[n],creds[n])
    open('registered.txt', 'wb').write(content)


def exchange_keys(raw_query, cls, c):
    username = raw_query.split(' !!!! ')[0]
    print '[*] API_KEY Received from %s' % c[0]
    try:
        api_key = raw_query.split(' !!!! ')[1]
        cls[api_key] = username
    except IndexError:
        print '[!!] Error during key exchange with %s' % c[0]
        return cls
    # Log this
    msg = '%s@%s=%s\n' % (username, c[0], api_key)
    if not os.path.isfile('registered.txt'):
        open('registered.txt', 'wb').write(msg)
    else:
        open('registered.txt', 'a').write(msg)
    return cls


def check_for_add_user_cmd(data, addr, existing):
    # Check for Add User Command
    query_user = data.split(' :::: ')[0]
    query_pass = ''
    legit_pass = False
    print '[*] Client Connected %s' % addr[0]
    try:
        query_pass = data.split(' :::: ')[1]
        print query_user
        print query_pass
        legit_pass = True
    except IndexError:
        pass
    if legit_pass and query_user not in existing:
        print '[*] Adding User: %s' % query_user
        open(query_user + '.pass', 'wb').write(query_pass)


def defragment(n_frags, name):
    raw_data = ''
    frag_files = utils.cmd('ls ../SHARED/chunk*')
    if len(frag_files) != n_frags:
        print '[!!] %d Fragments found (not %d)' % (len(frag_files), n_frags)
    for f in frag_files:
        raw_data += open(f, 'rb').read()
        os.remove('../SHARED/'+f)
    open('../SHARED/'+name, 'wb').write(raw_data)


def check_active():
    active = []
    if os.path.isfile('registered.txt'):
        for u in utils.swap('registered.txt', False):
            user = u.split('@')[0]
            ip = u.split('@')[1].split('=')[0]
            os.system('ping -c 1 %s >> p.txt' % ip)
            online = False
            # parse ping
            for line in utils.swap('p.txt', True):
                try:
                    ping = line.split('time=')[1]
                    online = True
                except IndexError:
                    pass
            if online:
                active.append(ip)
    print '[*] %d Peers are active' % len(active)
    refresh_registered_nodes()
    return active


class QueryApi:
    t0 = 0

    def __init__(self, start):
        self.t0 = start

    @staticmethod
    def show_peers(client, clients, raw, decrypted_query):
        # TODO: socket error handling
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        print '[*] Decrypted Query: %s' % decrypted_query
        try:
            if decrypted_query == 'show_peers':
                reply = utils.arr2lines(utils.cmd('ls ../*.pass'))
                encrypted_content = utils.EncodeAES(cipher, reply)
                client.send(encrypted_content)
            else:
                return client
        except IndexError:
            print '[!!] Error Decrypting Check Peers Command from %s' % clients[raw.split(' ???? ')[0]]
        return client

    @staticmethod
    def message_handler(client, clients, raw, decrypted_query):
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        print '[o] Incoming Message... '
        try:
            if decrypted_query == 'send_message':
                reply = utils.EncodeAES(cipher, 'READY!')
                client.send(reply)
                enc_data = client.recv(1500000)
                print ' [*] Message Received!'
                decrypted_data = utils.DecodeAES(cipher, enc_data)
                print decrypted_data
                open('messages.txt', 'a').write(decrypted_data)
        except IndexError:
            print '[!!] Message Handler Error'
        return client

    @staticmethod
    def show_shared_files(client, raw, decrypted_query):
        # TODO: socket error handling
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        get_shares = 'ls ../SHARED | while read n; do sha256sum ../SHARED/$n >> files.txt; done'
        try:
            if decrypted_query == 'show_shares':
                os.system(get_shares)
                client.send(utils.EncodeAES(cipher, utils.arr2lines(utils.swap('files.txt', True))))
            else:
                return client
        except IndexError:
            pass
        return client

    @staticmethod
    def file_upload(client, client_ip,raw, decrypted_query):
        # TODO: socket error handling
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        try:
            if 'PUT' in decrypted_query.split('_'):
                max_size = 2000
                name = decrypted_query.split('_')[1]
                size = int(decrypted_query.split('_')[2])
                if size < max_size:
                    print '[*] %s is uploading %d bytes' % (client_ip, size)
                    client.send(utils.EncodeAES(cipher, 'YES'))
                    raw_data = client.recv(size)
                    print '[*] %d Encrypted Bytes Received' % len(raw_data)
                    if len(raw_data) > 0:
                        try:
                            dec_data = utils.DecodeAES(cipher, raw_data)
                            open('../SHARED/%s' % name, 'wb').write(dec_data)
                        except ValueError:
                            print '[!!] Failed to decrypt data'
                            pass
                else:
                    client.send(utils.EncodeAES(cipher, 'NO'))
            elif 'GET' in decrypted_query.split('_'):
                name = '../SHARED/' + decrypted_query.split('_')[1]
                if os.path.isfile(name):
                    size = os.path.isfile(name)
                    print '[*] %s is requesting %s [%d bytes]' % (client_ip,
                                                                  name, size)
                    enc_data = utils.EncodeAES(cipher, open(name, 'rb').read())
                    client.send(enc_data)
            else:
                return client
        except IndexError:
            pass
        return client


def listen_alt_channel(timeout):
    clients = {}
    # refresh_registered_nodes()
    # TODO: Create a log file for this alternate channel
    tic = time.time(); running = True
    listener = utils.start_listener(54123, timeout)
    existing_users = utils.cmd('ls ../*.pass')
    print '[*] %d existing users' % len(existing_users)
    while running and (time.time()-tic) < timeout:

        check_active()

        try:
            client, client_addr = listener.accept()
            raw_data = client.recv(1028).replace('\n','')

            # Check for api_key exchange command
            if len(raw_data.split(' !!!! ')) == 2:
                clients = exchange_keys(raw_data, clients, client_addr)

            # Encrypted API Queries
            if len(raw_data.split(' ???? ')) >= 2 and raw_data.split(' ???? ')[0] in clients.keys():
                cipher = AES.new(base64.b64decode(raw_data.split(' ???? ')[0]))
                decrypted_query = utils.DecodeAES(cipher, raw_data.split(' ???? ')[1])

                # Display peer names command
                client = QueryApi.show_peers(client, clients, raw_data, decrypted_query)

                # Check for show shares command
                client = QueryApi.show_shared_files(client, raw_data, decrypted_query)

                # check for encrypted p2p messages
                client = QueryApi.message_handler(client, clients, raw_data, decrypted_query)

                if 'fragments' in decrypted_query.split(':'):
                    N = decrypted_query.split(':')[1].split(' = ')[0]
                    name_out = decrypted_query.split(' = ')[1]
                    print '[*] %s is requesting fragmented file re-assembly of %s fragments' %\
                          (client_addr[0], N)
                    defragment(int(N), name_out)

                # Upload file
                client = QueryApi.file_upload(client, client_addr[0], raw_data, decrypted_query)

            # Check for add user command
            check_for_add_user_cmd(raw_data,client_addr, existing_users)

            ''' CLOSE CONNECTION WITH REMOTE CLIENT '''
            client.close()
        except socket.error:
            print '[!!] Connection Error'
            running = False


if __name__ == '__main__':
    if '-l' in sys.argv and len(sys.argv) >= 3:
        timer = int(sys.argv[2])
        print '[*] Starting Backend Listener'
        listen_alt_channel(timer)
