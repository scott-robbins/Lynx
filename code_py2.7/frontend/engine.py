import socket
import utils
import time
import sys


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
                print query_user
                print query_user
                query_pass = raw_data.split('::::')[1]
                legit_pass = True
            except IndexError:
                pass
            if legit_pass:
                print '[*] Adding User: %s' % query_user
                open(query_user+'.pass','wb').write(query_pass)
                client.send('ACK')
            client.close()
        except socket.error:
            print '[!!] Connection Error'
            running = False


if __name__ == '__main__':
    if '-l' in sys.argv and len(sys.argv) >= 3:
        timer = int(sys.argv[2])
        print '[*] Starting Backend Listener'
        listen_for_new_users(timer)
