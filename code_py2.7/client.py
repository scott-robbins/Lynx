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
    # - [1] Create/Load Local Private Key
    private_key, public_key, shared_files = initialize_keys(private)

    # - [3] Create Key and Credentials
    login_data, username = create_username(private.replace('.','-')+'.pem')
    cloud_gateway = get_cloud_ip()

    # Register With Main Cloud Server
    network.connect_send(cloud_gateway, 54123, '../'+username+' :::: '+open(username+'.pass','rb').read(), 10)

    # Update/Sync with the P2P Cloud
    my_api_key = base64.b64encode(get_random_bytes(32))  # set api key
    network.connect_send(cloud_gateway, 54123, username+' !!!! '+my_api_key, 10)
    enc_query = utils.EncodeAES(AES.new(base64.b64decode(my_api_key)), 'show_peers')
    # test api key
    enc_reply = network.connect_receive(cloud_gateway, 54123, my_api_key+' ???? '+enc_query, 10)
    peer_list = utils.DecodeAES(AES.new(base64.b64decode(my_api_key)), enc_reply)
    print '[*] Remote Peer Has Provided A List of Active Peers:'
    for peer in peer_list:
        print '\t - %s' % peer

