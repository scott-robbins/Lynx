from Crypto.Cipher import AES
import base64
import socket
import utils
import time
import sys
import os


def exchange_keys(raw_query, cls, c):
    username = raw_query.split(' !!!! ')[0]
    print '[*] API_KEY Received from %s' % c[0]
    try:
        api_key = raw_query.split(' !!!! ')[1]
        cls[api_key] = username
    except IndexError:
        print '[!!] Error during key exchange with %s' % c[0]
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
        os.remove('../SHARED/chunk/'+f)
    open('../SHARED/'+name, 'wb').write(raw_data)


def listen_alt_channel(timeout):
    clients = {}
    # TODO: Create a log file for this alternate channel
    tic = time.time(); running = True
    listener = utils.start_listener(54123, timeout)
    existing_users = utils.cmd('ls ../*.pass')
    print '[*] %d existing users' % len(existing_users)
    while running and (time.time()-tic) < timeout:
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
                print '[*] Decrypted Query: %s' % decrypted_query
                # Check for check peer names command
                try:

                    if decrypted_query == 'show_peers':
                        reply = utils.arr2lines(utils.cmd('ls ../*.pass'))
                        encrypted_content = utils.EncodeAES(cipher, reply)
                        client.send(encrypted_content)
                except IndexError:
                    print '[!!] Error Decrypting Check Peers Command from %s' % clients[raw_data.split(' ???? ')[0]]

                # Check for show shares command
                try:
                    if decrypted_query == 'show_shares':
                        get_shares = 'ls ../SHARED | while read n; do sha256sum ../SHARED/$n >> files.txt; done'
                        os.system(get_shares)
                        clear_reply = utils.arr2lines(utils.swap('files.txt', True))
                        client.send(utils.EncodeAES(cipher, clear_reply))
                except IndexError:
                    pass
                if 'fragments' in decrypted_query.split(':'):
                    N = decrypted_query.split(':')[1].split(' = ')[0]
                    name_out = decrypted_query.split(' = ')[1]
                    print '[*] %s is requesting fragmented file re-assembly of %s fragments' %\
                          (client_addr[0], N)
                    defragment(int(N), name_out)
                # Upload file
                try:
                    if 'PUT' in decrypted_query.split('_'):
                        max_size = 2000
                        name = decrypted_query.split('_')[1]
                        size = int(decrypted_query.split('_')[2])
                        if size < max_size:
                            print '[*] %s is uploading %d bytes' % (client_addr[0], size)
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
                        name = '../SHARED/'+decrypted_query.split('_')[1]
                        if os.path.isfile(name):
                            size = os.path.isfile(name)
                            print '[*] %s is requesting %s [%d bytes]' % (client_addr[0],
                                                                          name, size)
                            enc_data = utils.EncodeAES(cipher, open(name, 'rb').read())
                            client.send(enc_data)
                except IndexError:
                    pass
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
