from Crypto.Random import get_random_bytes
import base64
import socket
import utils
import time
import sys
import os


def create_account():
    # print ''
    # print ''
    # print ''
    username = raw_input('Enter a username: ')
    os.mkdir('UserData')
    # See if it's available
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('beta.lynx-network.us', 54123))
        s.send(username)
        # wait a few seconds for a reply
        recvd = False; dt = time.time()
        while not recvd and (time.time()-dt)<3:
            reply = s.recv(1024)
            print reply
            if '[!!]' not in reply.split(' '):
                open('UserData/%s.token'%username, 'wb').write(reply)
            else:
                print '[!!] That username is taken...' # TODO: write server side logic for retry
                exit()
            break
    except socket.error:
        print '[!!] Unable to connect to remote server...'
        print '** Are you running as root?'
        exit()
    return reply, username




if __name__ == '__main__':
    new_user = False
    # Check for UserProfile
    if not os.path.isdir('UserData'):
        user_token, username = create_account()

