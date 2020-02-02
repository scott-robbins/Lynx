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
    query = 'GET_%s' % fname
    encq = utils.EncodeAES(cipher, query)
    print '[*] Requesting Lynx Cloud for file %s' % fname
    encr = network.connect_receive(cloud_gateway, 54123, mykey + ' ???? ' + encq, 10)
    open('SHARED/%s' % fname, 'wb').write(utils.DecodeAES(cipher, encr))
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
    private_key, public_key, shared_files = initialize_keys(private)
    # - [3] Create Key and Credentials
    if not utils.cmd('ls *.pass'):
        login_data, username = create_username(private.replace('.','-')+'.pem')
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
    network.connect_send(cloud_gateway, 54123, username+' !!!! '+my_api_key, 10)
    cipher = AES.new(base64.b64decode(my_api_key))

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
            # TODO: Alert remote host about fragments coming
            print '[*] File is %d bytes (over 1.5kB)' % sz
            fragments = network.fragmented(n, 1000)
            N = 0
            for file_name in os.listdir('chunks'):
                os.system('mv chunks/%s $PWD' % file_name)
                put_file(file_name, my_api_key)
                os.remove(file_name)
                N += 1
            os.system('rm -r chunks/')
            # TODO: Let remote host they can reassemble now
            network.connect_send(cloud_gateway,54123,my_api_key+' ???? fragments:%d' % N,10)
        put_file(n, my_api_key)     # TODO: This breaking for some reason after about 1.5kB

    if 'get' in sys.argv and len(sys.argv) >= 3:
        n = sys.argv[2]
        get_file(n,my_api_key)     # TODO: This breaking for some reason after about 2.5kB

    # TODO: make utility fcn that tests up/down breakpoint on file size
    #  (until I can figure out how to prevent it)
