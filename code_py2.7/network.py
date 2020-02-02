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
    s.close()
    return 'DONE'


def connect_receive(remote_address, remote_port, query, timeout):
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
        s.send(query)
    except socket.error:
        print '[!!] Unable to connect to %s' % remote_address
        return ''
    # Now Get a Reply
    tic = time.time(); unacknowledged = True; reply = ''
    while unacknowledged and (time.time() - tic) < timeout:
        try:
            reply = s.recv(1250000)
            unacknowledged = False
            print '[*] %d Bytes Received' % len(reply)
        except socket.error:
            print '[!!] Connection Broken'
            break
    s.close()
    return reply


def connect_receive_send(remote_address, remote_port, query, data, cipher):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print '[!!] Error Creating Socket...'
        return ''
    try:
        s.connect((remote_address, remote_port))
        s.send(query)
    except socket.error:
        print '[!!] Unable to connect to %s' % remote_address
        return ''
    # Now Get a Reply
    reply = utils.DecodeAES(cipher, s.recv(2048))
    if reply == 'YES':
        print '[*] Sending %s %d bytes of data' % (remote_address, len(data))
        s.send(data)
    s.close()
    return reply


def fragmented(fname, frag_size):
    if not os.path.isfile(fname):
        print "[!] Cannot find %s" % fname
    else:
        n_files = os.path.getsize(fname)/frag_size
        print '[*] Fragmenting %s into %d files' % (fname, n_files)
        os.system('mkdir chunks/')
        raw_data = open(fname,'rb').read()
        block_ind = 1
        blocks = range(0,len(raw_data), frag_size)
        fragments = {'name': fname,
                     'frags': []}

        for ii in blocks:
            try:
                a = blocks[block_ind - 1]
                b = blocks[block_ind]
                print 'data[%d:%d]' % (a, b)
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
            print 'Adding %d bytes' % db
            fname = 'chunk%d.frag' % (block_ind+1)
            fragments['frags'].append('chunks/' + fname)
            open('chunks/' + fname, 'wb').write(chunk)
        return fragments
