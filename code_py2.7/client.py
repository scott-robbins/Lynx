from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import socket
import base64
import network
import utils
import time
import sys
import os


def create_username(key_file):
    print 'This is your internet login password: '
    os.system('sha256sum %s >> hash.txt' % key_file)
    login = utils.swap('hash.txt', True).pop().split(' ').pop(0)
    print login
    print 'You can visit %s to Login ater we are done here.' % domain
    uname = str(raw_input('Enter the username you will login with: '))
    open(uname + '.pass', 'wb').write(login)
    return login, uname


def get_cloud_ip():
    ip = ''
    os.system('ping -c 1 stickysprings.bounceme.net >> host.txt')
    for line in utils.swap('host.txt', True):
        try:
            ip = line.split(' 56(84)')[0].split('(')[1].split(')')[0]
        except IndexError:
            pass
    return ip


def initialize_keys(private_ip):
    print private_ip
    key_file_name = private_ip.replace('.', '-') + '.pem' # TODO: Should this be public or private ip?
    priv = utils.load_private_key(key_file_name)
    pub = priv.publickey()
    # - [2] Create or Load a SHARED/ Folder
    if not os.path.isdir('SHARED'):
        os.mkdir('SHARED')
        shares = []
    else:
        shares = os.listdir('SHARED')
    print '[*] %d files in SHARED/ Folder' % len(shares)
    return priv, pub, shares


def get_file(fname, mykey):
    # TODO: Use the fragmentation method like the serverside PUT code, so that client can
    #  GET files that are over ~1.5Kb
    query = 'GET_%s' % fname
    encq = utils.EncodeAES(cipher, query)
    print '[*] Requesting Lynx Cloud for file %s' % fname
    encr = network.connect_receive(cloud_gateway, 54123, mykey + ' ???? ' + encq, 10)
    decr = utils.DecodeAES(cipher, encr)
    if len(decr.split(':')) <= 1:
        open('SHARED/%s' % fname, 'wb').write(decr)
    else:
        file_size = int(decr.split('-')[1].split('-')[0])
        n_fragments = int(decr.split('-')[2])
        print '[*] Remote File is %d bytes.\n' \
              '[o] Download will be in %d fragments...' % (file_size, n_fragments)
        # Now Download those fragments, and recombine
        recombined = False
        n_recv = 0
        while not recombined:
            if n_recv == n_fragments:
                target = 'SHARED/%s' % fname
                cmb = 'ls *.frag | while read n; do cat $n >> %s;rm $n; done' % target
                os.system(cmb)
                recombined = True
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((cloud_gateway, 54123))
                raw_chunk = s.recv(2048)
                s.send('GOT:%d' % len(raw_chunk))
                s.close()
                open('chunk%d.frag' % n_recv, 'wb').write(utils.DecodeAES(cipher, raw_chunk))
                n_recv += 1
            except socket:
                print '[!!] Failed to create socket... Are you running as root?'
                exit()
        print '[*] %d Fragments Received and Recombined into %s [%d bytes]' % \
              (n_fragments, fname, file_size)

    return len(encr)


def put_file(fname, mykey):
    enc_data = utils.EncodeAES(cipher, open(fname, 'rb').read())
    size = len(enc_data)
    query = 'PUT_%s_%s' % (fname, size)
    print '[*] Querying %s...' % query
    encq = utils.EncodeAES(cipher, query)
    qstr = mykey + ' ???? ' + encq
    result = network.connect_receive_send(cloud_gateway, 54123, qstr, enc_data, cipher)
    return result


def show_peers(mykey):
    enc_query = utils.EncodeAES(cipher, 'show_peers')
    enc_reply = network.connect_receive(cloud_gateway, 54123, mykey + ' ???? ' + enc_query, 10)
    peer_list = utils.DecodeAES(cipher, enc_reply).split('\n')
    peer_list.remove('')
    print '[*] Remote Peer Has Provided A List of %d Peers:' % len(peer_list)
    for name in peer_list:
        print '  -> ' + name.replace('../', '').split('.pass')[0]
    return peer_list


def show_shared(mykey):
    enc_shares_request = utils.EncodeAES(AES.new(base64.b64decode(mykey)), 'show_shares')
    enc_shares_query = mykey + ' ???? ' + enc_shares_request
    enc_shares = network.connect_receive(cloud_gateway, 54123, enc_shares_query, 10)
    remote_shares = utils.DecodeAES(AES.new(base64.b64decode(mykey)), enc_shares)
    print '[*] Remote Peer has following data in SHARED/ folder:\n%s' % remote_shares
    return remote_shares


def send_message(mykey, sender, receiver, data):
    c = AES.new(base64.b64decode(mykey))
    enc_send_request = utils.EncodeAES(c, 'send_message')
    enc_send_query = mykey+' ???? '+enc_send_request
    clear_content = '%s->%s: %s' % (sender, receiver, data)
    enc_content = utils.EncodeAES(c, clear_content)
    network.connect_receive_send(cloud_gateway,54123,enc_send_query,enc_content, c)


if __name__ == '__main__':
    verbose = True  # TODO: DEBUG setting
    date, localtime = utils.create_timestamp()
    print '[{(~\033[1m LYNX CLIENT \033[0m~)}]\t\t%s - %s' % (localtime, date)
    domain = 'http://stickysprings.bounceme.net'

    # get operating system. this is currently only designed for linux!
    if os.name == 'nt':
        print '[!!] Operating System is WINDOWS. This software only ' \
              'supports Linux as of now.'
        exit()
    # Get external/internal nx info
    public, private, nic_name = utils.get_nx_info(verbose=False)

    # Register locally
    cloud_gateway = get_cloud_ip()
    # - [1] Create/Load Local Private Key
    private_key, public_key, shared_files = initialize_keys(public)
    # - [3] Create Key and Credentials
    if not utils.cmd('ls *.pass'):
        login_data, username = create_username(public.replace('.','-')+'.pem')
        # Register With Main Cloud Server
        network.connect_send(cloud_gateway, 54123, '../' + username + ' :::: ' + open(username + '.pass', 'rb').read(), 10)
    else:
        pass_file_list = utils.cmd('ls *.pass')
        if len(pass_file_list)>=1:
            pass_file = pass_file_list.pop()
        login_data = open(pass_file, 'rb').read()
        username = pass_file.split('.pass')[0]

    # Update/Sync with the P2P Cloud
    my_api_key = base64.b64encode(get_random_bytes(32))  # set api key
    cipher = AES.new(base64.b64decode(my_api_key))

    if '-peer' not in sys.argv:
        network.connect_send(cloud_gateway, 54123, username+' !!!! '+my_api_key, 10)
    else:
        ii = 0
        for e in sys.argv:
            if e != '-peer':
                ii += 1
            else:
                ii = ii + 1
                break
        print 'synchronizing with PEER %s' % sys.argv[ii]
        network.connect_send(sys.argv[ii],54123, username + ' !!!! ' + my_api_key, 10)

    if 'peers' in sys.argv:  # show registed peers using api key
        show_peers(my_api_key)

    if 'shares' in sys.argv:
        show_shared(my_api_key)

    if 'put' in sys.argv and len(sys.argv) >= 3:
        if not os.path.isfile(sys.argv[2]):
            print '[!!] Cannot find file %s' % sys.argv[2]
        n = sys.argv[2]
        sz = os.path.getsize(n)
        if sz > 1500:
            fragments = network.fragmented(n, 800)
            N = len(fragments['frags'])
            # TODO: Alert remote host about fragments coming
            msg = utils.EncodeAES(cipher, 'incoming_file:%s' % n)
            network.connect_send(cloud_gateway, 54123, my_api_key+' ???? '+msg,10)
            print '[*] File is %d bytes (over 1.5kB)' % sz

            N = 0
            for file_name in os.listdir('chunks'):
                os.system('mv chunks/%s $PWD' % file_name)
                put_file(file_name, my_api_key)
                os.remove(file_name)
                N += 1
            os.system('rm -r chunks/')
            encr = utils.EncodeAES(cipher, 'fragments:%d = %s' % (N, n))
            network.connect_send(cloud_gateway, 54123, my_api_key + ' ???? '+encr, 10)
        else:
            put_file(n, my_api_key)     # TODO: This breaking for some reason after about 1.5kB

    if 'get' in sys.argv and len(sys.argv) >= 3:
        n = sys.argv[2]
        get_file(n,my_api_key)

    if 'register' in sys.argv:
        public, private, nic_name = utils.get_nx_info(verbose=False)
        # Register locally
        cloud_gateway = get_cloud_ip()
        # - [1] Create/Load Local Private Key
        private_key, public_key, shared_files = initialize_keys(private)
        login_data, username = create_username(private.replace('.', '-') + '.pem')
        # Register With Main Cloud Server
        network.connect_send(cloud_gateway, 54123, '../'+username+' :::: '+open(username+'.pass', 'rb').read(), 10)

    if 'send' in sys.argv:
        sender = raw_input('Enter Username: \n')
        receiver = raw_input('Enter Recipient: \n')
        msg = False; file_transfer = False
        if raw_input('Do you want to send a message? (Y/N):\n').upper()=='Y':
            msg = True
        if not msg:
            if raw_input('Do you want to send a file (Y/N)?:\n')=='Y':
                file_transfer = True
        if not msg and not file_transfer:
            print '** Incorrect Usage!! **'
            exit()
        if msg:
            data = raw_input('> ')
            send_message(my_api_key, sender, receiver, data)

