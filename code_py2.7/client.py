from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
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

    if 'peers' in sys.argv:  # show registed peers using api key
        enc_query = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), 'show_peers')
        enc_reply = network.connect_receive(cloud_gateway, 54123, my_api_key + ' ???? ' + enc_query, 10)
        peer_list = utils.DecodeAES(AES.new(base64.b64decode(my_api_key)), enc_reply).split('\n')
        peer_list.remove('')
        print '[*] Remote Peer Has Provided A List of %d Peers:' % len(peer_list)
        for name in peer_list:
            print '  -> '+name.replace('../', '').split('.pass')[0]

    if 'shares' in sys.argv:
        enc_shares_request = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), 'show_shares')
        enc_shares_query = my_api_key + ' ???? ' + enc_shares_request
        enc_shares = network.connect_receive(cloud_gateway, 54123, enc_shares_query, 10)
        print '[*] Remote Peer has following data in SHARED/ folder:'
        remote_shares = utils.DecodeAES(AES.new(base64.b64decode(my_api_key)), enc_shares)
        print remote_shares

    # Send a direct message to another peer
    if 'send' in sys.argv and len(sys.argv) >= 4:
        peer = sys.argv[2]
        msg = utils.arr2str(sys.argv[3:])
        clear_query = my_api_key+' ???? send_message;;%s;;%s' % (peer, msg)
        enc_q = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), clear_query)
        enc_ack = network.connect_receive(cloud_gateway, 54123, enc_q, 10)

    if 'put' in sys.argv and len(sys.argv) >= 3:
        if not os.path.isfile(sys.argv[2]):
            print '[!!] Cannot find file %s' % sys.argv[2]
        name = sys.argv[2]
        size = os.path.getsize(name)
        query = 'PUT_%s_%s' % (name, size)
        print '[*] Querying %s...' % query

        # encrypted_query = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), query)
        # enc_ack = network.connect_receive(cloud_gateway, 54123, encrypted_query, 10)
        # reply = utils.DecodeAES(AES.new(base64.b64decode(my_api_key)), enc_ack)
        # print reply
        enc_query = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), query)
        enc_reply = network.connect_receive(cloud_gateway, 54123, my_api_key + ' ???? ' + enc_query, 10)
        reply = utils.DecodeAES(AES.new(base64.b64decode(my_api_key)), enc_reply)
        if reply == 'YES':
            cipher = AES.new(base64.b64decode(my_api_key))
            print '[*] Remote host accepted put_file request [%d bytes]' % size
            encrypted_data = utils.EncodeAES(cipher, open(name, 'rb').read())
            network.connect_send(cloud_gateway,54123,encrypted_data,20)
        else:
            print '[*] Remote host declined put_file request'
