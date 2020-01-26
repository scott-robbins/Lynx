from Crypto.Cipher import AES
import base64
import socket
import utils
import time
import sys
import os


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
                username = raw_data.split(' !!!! ')[0]
                print '[*] API_KEY Received from %s' % client_addr[0]
                try:

                    api_key = raw_data.split(' !!!! ')[1]
                    clients[api_key] = username
                except IndexError:
                    print '[!!] Error during key exchange with %s' % client_addr[0]
            # Encypted API Queries
            if len(raw_data.split(' ???? ')) >= 2 and raw_data.split(' ???? ')[0] in clients.keys():
                cipher = AES.new(base64.b64decode(raw_data.split(' ???? ')[0]))

                # Check for check peer names command
                try:
                    decrypted_query = utils.DecodeAES(cipher, raw_data.split(' ???? ')[1])
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
                    print

            # Check for Add User Command
            query_user = raw_data.split(' :::: ')[0]
            query_pass = ''
            legit_pass = False
            print '[*] Client Connected %s' % client_addr[0]
            try:
                query_pass = raw_data.split(' :::: ')[1]
                print query_user
                print query_pass
                legit_pass = True
            except IndexError:
                pass
            if legit_pass and query_user not in existing_users:
                print '[*] Adding User: %s' % query_user
                open(query_user+'.pass','wb').write(query_pass)
            client.close()
        except socket.error:
            print '[!!] Connection Error'
            running = False


if __name__ == '__main__':
    if '-l' in sys.argv and len(sys.argv) >= 3:
        timer = int(sys.argv[2])
        print '[*] Starting Backend Listener'
        listen_alt_channel(timer)