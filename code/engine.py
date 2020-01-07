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


