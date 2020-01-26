import socket
import utils
import time
import os


def listen_for_new_users(timeout):
    tic = time.time(); running = True
    listener = utils.start_listener(54123, timeout)
    existing_users = utils.cmd('ls ../*.pass')
    print '[*] %d existing users' % len(existing_users)
    while running and (time.time()-tic) < timeout:
        try:
            client, client_addr = listener.accept()
            raw_data = client.recv(1028)
            query_user = raw_data.split('::::')[0]
            query_pass = ''
            legit_pass = False
            try:
                query_pass = raw_data.split('::::')[1]
                legit_pass = True
            except IndexError:
                pass
            if legit_pass:
                print '[*] Adding User: %s' % query_user
                open(query_user+'.pass','wb').write(query_pass)
        except socket.error:
            print '[!!] Connection Error'
            running = False
