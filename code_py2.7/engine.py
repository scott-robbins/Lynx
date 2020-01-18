from Crypto.PublicKey import RSA
import utils
import os


def get_public_private_ip(verbose):
    private = ''
    public = ''
    iface = ''
    if os.path.isfile('nx.txt'):
        for line in utils.swap('nx.txt', False):
            try:
                public = line.split('Public IP:\t')[1]
            except IndexError:
                pass
            try:
                private = line.split('Private IP:\t')[1]
            except IndexError:
                pass
            try:
                iface = line.split('Nx Iface:\t')[1]
            except IndexError:
                pass
    else:
        os.system('sh get_network_addresses.sh')
        for line in utils.swap('nx.txt', False):
            try:
                public = line.split('Public IP:\t')[1]
            except IndexError:
                pass
            try:
                private = line.split('Private IP:\t')[1]
            except IndexError:
                pass
            try:
                iface = line.split('Nx Iface:\t')[1]
            except IndexError:
                pass
    if verbose:
        print 'Private IP:\t%s' % private
        print 'Public IP:\t%s' % public
        print 'Network Iface:\t%s' % iface
    return private, public, iface


def create_rsa_key(name):
    key = RSA.generate(2048)
    f = open('%s' % name, 'wb')
    f.write(key.exportKey('PEM'))
    f.close()
    return key


def load_private_key(name):
    if os.path.isfile(name):
        private_key = RSA.importKey(open(name, 'rb').read())
    else:
        private_key = create_rsa_key(name)
    return private_key


def parse_ping(result):
    open('ping.txt', 'wb').write(result)
    routable = False
    ping_time = 0
    for line in utils.swap('ping.txt', True):
        try:
            ping_time = float(line.split('time=')[1].split(' ')[0])
            routable = True
        except IndexError:
            pass
    return routable, ping_time


def crawl_dir(file_path, verbose):
    directory = {'dir': [], 'file': []}
    hashes = {}
    folders = [file_path]
    while len(folders) > 0:
        direct = folders.pop()
        if verbose:
            print 'Exploring %s' % direct
        for item in os.listdir(direct):
            if os.path.isfile(direct + '/' + item):
                file_name = direct + "/" + item
                directory['file'].append(file_name)
                hashes[file_name] = get_sha256_sum(file_name, False)
            else:
                directory['dir'].append(direct + '/' + item)
                folders.append(direct + '/' + item)
    return directory, hashes


def get_sha256_sum(file_name, verbose):
    if len(file_name.split("'")) >= 2:
        file_name = ("{!r:}".format(file_name))
        os.system("sha256sum "+file_name + ' >> out.txt')
    else:
        os.system("sha256sum '%s' >> out.txt" % file_name)
    try:
        sum_data = utils.swap('out.txt', True).pop().split(' ')[0]
    except:
        print file_name
    if verbose:
        print sum_data
    return sum_data


def parse_manifest_file(file_name):
    shared_data = {}
    for line in utils.swap(file_name, False):
        try:
            file_hash = line.split(' = ')[1]
            file_name = line.split(' = ')[0]
            shared_data[file_name] = file_hash
        except IndexError:
            pass
    return shared_data


def log_known_peers(verbose):
    peer_list = ''
    n_peers = 0
    for name in utils.cmd('ls *.pem'):
        peer_list += name.replace('-','.')+'\n'
        n_peers += 1
    # Encrypt this
    utils.encrypt_file(peer_list, 'peers.txt')
    if verbose:
        print '[*] %d Peers Logged' % n_peers
        print '[*] Encrypted Peer List in peers.txt'
