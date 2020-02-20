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
    try:
        query_pass = data.split(' :::: ')[1]
        legit_pass = True
    except IndexError:
        pass
    if legit_pass and query_user not in existing:
        print '[*] Adding User: %s' % query_user
        open(query_user + '.pass', 'wb').write(query_pass)


def defragment(n_frags, name):
    raw_data = ''
    frag_files = utils.cmd('ls chunks/')
    if len(frag_files) != n_frags:
        print '[!!] %d Fragments found (not %d)' % (len(frag_files), n_frags)
    for f in range(1, n_frags+1):
        # print '[o] Recombining file chunk%d.frag' % f
        raw_data += open('chunks/chunk%d.frag' % f, 'rb').read()
        os.remove('chunks/chunk%d.frag' % f)
    os.system('rm -rf chunks/')
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


def fragmented(fname, frag_size):
    if not os.path.isfile(fname):
        print "[!] Cannot find %s" % fname
    else:
        n_files = os.path.getsize(fname)/frag_size
        print '[*] Fragmenting %s into %d files' % (fname, n_files)
        if os.path.isdir('chunks/'):
            os.system('rm -rf chunks; mkdir chunks/')
        else:
            os.mkdir('chunks')
        raw_data = open(fname,'rb').read()
        block_ind = 1
        blocks = range(0,len(raw_data), frag_size)
        fragments = {'name': fname,
                     'frags': []}

        for ii in blocks:
            try:
                a = blocks[block_ind - 1]
                b = blocks[block_ind]
                # print 'data[%d:%d]' % (a, b)
                chunk = raw_data[a:b]
                fname = 'chunk%d.frag' % block_ind
                open('chunks/' + fname, 'wb').write(chunk)
                fragments['frags'].append('chunks/' + fname)
                block_ind += 1
            except IndexError:
                pass
        if blocks[len(blocks)-1] < len(raw_data):
            db = len(raw_data) - blocks[len(blocks)-1]
            chunk = raw_data[blocks[len(blocks)-1]:(blocks[len(blocks)-1]+db)]
            # print 'Adding %d bytes' % db
            fname = 'chunk%d.frag' % (len(blocks))
            fragments['frags'].append('chunks/' + fname)
            open('chunks/' + fname, 'wb').write(chunk)
        return fragments


class QueryApi:
    t0 = 0

    def __init__(self, start):
        self.t0 = start

    @staticmethod
    def show_peers(client, clients, raw, decrypted_query):
        # TODO: socket error handling
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        try:
            if 'show_peers' in decrypted_query.split(': '):
                reply = utils.arr2lines(utils.cmd('ls ../*.pass'))
                encrypted_content = utils.EncodeAES(cipher, reply)
                if len(encrypted_content) < 1500:
                    client.send(encrypted_content)
                else:
                    open('shared_data.txt', 'wb').write(encrypted_content)
                    fragments = fragmented('shared_data.txt', 800)
                    n_frags = len(fragments['frags'])
                    print '[*] Fragmenting shared file data into %d packets' % n_frags
                    os.remove('shared_data.txt')
                    os.system('rm -rf chunks/')
        except IndexError:
            print '[!!] Error Decrypting Check Peers Command from %s' % clients[raw.split(' ???? ')[0]]
        return client

    @staticmethod
    def message_handler(client, clients, raw, decrypted_query):
        cipher = AES.new(base64.b64decode(raw.split(' ???? ')[0]))
        # print '[o] Incoming Message... '
        try:
            client.send(utils.EncodeAES(cipher, 'YES'))
            enc_data = client.recv(1500000)
            # print ' [*] Message Received!'
            decrypted_data = utils.DecodeAES(cipher, enc_data)
            # print decrypted_data
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
            if 'show_shares' in decrypted_query.split(':'):
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
        api_key = base64.b64decode(raw.split(' ???? ')[0])
        cipher = AES.new(api_key)
        if not os.path.isdir('chunks/'):
            os.mkdir('chunks/')
        else:
            os.system('rm -rf chunks; mkdir chunks')
        try:
            if 'PUT' in decrypted_query.split('_'):
                max_size = 2000
                name = decrypted_query.split('_')[1]
                size = int(decrypted_query.split('_')[2])
                if size < max_size:
                    # print '[*] %s is uploading %d bytes' % (client_ip, size)
                    client.send(utils.EncodeAES(cipher, 'YES'))
                    raw_data = client.recv(size)
                    # print '[*] %d Encrypted Bytes Received' % len(raw_data)
                    if len(raw_data) > 0:
                        try:
                            dec_data = utils.DecodeAES(cipher, raw_data)
                            open('%s' % name, 'wb').write(dec_data)
                            client.close()
                            return client
                        except ValueError:
                            print '[!!] Failed to decrypt data'
                            pass
                else:
                    client.send(utils.EncodeAES(cipher, 'NO'))
            elif 'GET' in decrypted_query.split('_'):
                name = '../SHARED/' + decrypted_query.split('_')[1]
                if os.path.isfile(name):
                    size = os.path.getsize(name)
                    if size > 1100:
                        print '[*] Fragmenting download'
                        fragments = fragmented(name, 800)
                        n_frags = len(fragments['frags'])
                        msg_head = utils.EncodeAES(cipher, 'incoming_file:%s-%d-%d' % (name, size,n_frags))
                        client.send(msg_head, 10)
                        chunks_sent = 0
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.bind(('0.0.0.0', 54124))
                        s.listen(5)
                        bytes_sent = 0
                        print '[*] Receiving %d Fragments' % n_frags
                        for frag in fragments['frags']:
                            raw_data = open(frag, 'rb').read()
                            enc_data = utils.EncodeAES(cipher, raw_data)
                            rmt, rmt_addr = s.accept()
                            rmt.send(enc_data)
                            bytes_sent += int(rmt.recv(256).split(':')[1])
                            chunks_sent += 1
                            rmt.close()

                        os.system('rm -rf chunks/')
                        s.close()
                        return client
                    else:
                        print '[*] %s is requesting %s [%d bytes]' % (client_ip,
                                                                  name, size)
                        enc_data = utils.EncodeAES(cipher, open(name, 'rb').read())
                        client.send(enc_data)
            else:
                return client
        except IndexError:
            s.close()
            pass
        return client


def listen_alt_channel(timeout):
    clients = {}
    refresh_registered_nodes()
    # TODO: Create a log file for this alternate channel
    tic = time.time(); running = True
    listener = utils.start_listener(54123, timeout)
    existing_users = utils.cmd('ls ../*.pass')
    print '[*] %d existing users' % len(existing_users)
    while running and (time.time()-tic) < timeout:
        if os.path.isdir('chunks/'):
            os.system('sudo rm -rf chunks/')
        # check_active()
        # TODO: Improve performance by using dictionary of function calls like server
        try:
            client, client_addr = listener.accept()
            raw_data = client.recv(1028).replace('\n','')

            # Check for api_key exchange command
            if len(raw_data.split(' !!!! ')) == 2:
                clients = exchange_keys(raw_data, clients, client_addr)

            # Encrypted API Queries
            if len(raw_data.split(' ???? ')) >= 2:
                if raw_data.split(' ???? ')[0] not in clients.keys():
                    donothin = 0
                    # print '[*] Do not recognize key: %s from %s '% \
                    #       (raw_data.split(' ???? ')[0], client_addr[0])
                cipher = AES.new(base64.b64decode(raw_data.split(' ???? ')[0]))
                decrypted_query = utils.DecodeAES(cipher, raw_data.split(' ???? ')[1])

                if 'PUT' in decrypted_query.split('_') or 'GET' in decrypted_query.split('_'):
                    # Upload file
                    print '[*] %s in uploading a file' % client_addr[0]
                    client = QueryApi.file_upload(client, client_addr[0], raw_data, decrypted_query)

                if decrypted_query == 'cam_ready':
                    print '[*] CamReady Message Received'

                # Display peer names command
                client = QueryApi.show_peers(client, clients, raw_data, decrypted_query)

                # Check for show shares command
                client = QueryApi.show_shared_files(client, raw_data, decrypted_query)


                if decrypted_query == 'send_message':
                    # check for encrypted p2p messages
                    client = QueryApi.message_handler(client, clients, raw_data, decrypted_query)

                elif 'fragments' in decrypted_query.split(':'):
                    N = decrypted_query.split(':')[1].split(' = ')[0]
                    name_out = decrypted_query.split(' = ')[1]
                    print '[*] %s is requesting fragmented file re-assembly of %s fragments' %\
                          (client_addr[0], N)
                    defragment(int(N), name_out)
                    os.system('rm -rf chunks/')     # TODO: Why isn't this working??

            else:
                print raw_data
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
        print '[*] Starting Backend Server'
        listen_alt_channel(timer)
