import socket
import utils
import time
import os


def connect_send(remote_address, remote_port, msg, timeout):
    """
    Connect_Send - connects to a remote machine (at the given remote port)
    and sends the message provided. The function then listens (for the defined
    timeout, in seconds) for a reply. If the timeout expires the function will
    return empty char '', otherwise it will reply up to 65k of data.
    :param remote_address:
    :param remote_port:
    :param msg:
    :param timeout:
    :return:
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print '[!!] Error Creating Socket...'
        return ''
    try:
        s.connect((remote_address, remote_port))
        s.send(msg)
    except socket.error:
        print '[!!] Failed to connect to %s' % remote_address
        return ''
    # Now Get a Reply
    tic = time.time(); unacknowledged = True; reply = ''
    while unacknowledged and (time.time()-tic) < timeout:
        try:
            reply = s.recv(65000)
            unacknowledged = False
        except socket.error:
            print '[!!] Connection Broken'
            break
    s.close()
    return reply


def connect_receive(remote_address, remote_port, timeout):
    """
    CONNECT_RECEIVE - connects to a remote machine (at the given remote port)
    and receives a message (within a given timeout). If the timeout expires
    before a reply is received, the function returns and empty character ''.
    Otherwise, up to 100kb is retrieved and returned.
    :param remote_address:
    :param remote_port:
    :param timeout:
    :return:
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print '[!!] Error Creating Socket...'
        return ''
    try:
        s.connect((remote_address, remote_port))
    except socket.error:
        print '[!!] Unable to connect to %s' % remote_address
        return ''
    # Now Get a Reply
    tic = time.time(); unacknowledged = True; reply = ''
    while unacknowledged and (time.time() - tic) < timeout:
        try:
            reply = s.recv(125000)
            unacknowledged = False
            print '[*] %d Bytes Received' % len(reply)
        except socket.error:
            print '[!!] Connection Broken'
            break
    s.close()
    return reply


