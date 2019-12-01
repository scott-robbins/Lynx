from Crypto.PublicKey import RSA
import random
import base64
import socket
import time
import sys
import os

charfeed = 'abcdefghijklmnopqrstuvwxyz ?!)(&=*^%$#@}{][\\|/";:,.<>'
#      ########################### BASIC CRYPTO FUNCTIONS #############################      #
BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# Ex. Usage:
# key_init = os.urandom(BLOCK_SIZE)
# secret = 'PasswordKeyBasedDerivation_0'
# cipher = EncodeAES(AES.new(key_init), secret)
# plain = DecodeAES(AES.new(key_init), cipher)


def swap(file_name, destroy):
    data = []
    for line in open(file_name, 'r').readlines():
        data.append(line.replace('\n', ''))
    if destroy:
        os.remove(file_name)
    return data


def get_local_ip():
    os.system('ifconfig | grep broadcast >> inet.txt')
    ip = open('inet.txt', 'r').read().split('netmask')[0].split('inet')[1].replace(' ', '')
    os.remove('inet.txt')
    return ip

def get_ext_ip():
    cmd = 'echo $(GET https://api.ipify.org) >> ext.txt'
    return swap(cmd, True).pop()

def get_ext_ip_info():
    cmd = 'echo $(GET https://ipinfo.io/$(GET https://api.ipify.org)) >> ext_ip.txt'
    os.system(cmd)
    return swap('ext_ip.txt', True).pop()


def create_listening_socket(p, verbose):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', p))
        s.listen(5)
        if verbose:
            print '[*] Listening on %d' % p
        n = p
    except socket.error:
        try:        # This should hopefully handle cases where old cnxs are lingering
            n = random.randint(1025, 65000)
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', n))
            s.listen(5)
            if verbose:
                print '[*] Listening on %d' % n
        except socket.error:
            print '[!!] Error creating socket'
            s.close()
    return s, n


def send_and_wait(addr, port, message, timeout):
    tic = time.time()
    reply = ''
    while time.time()-tic < timeout:
        try:
            print 'Sending %s to %s:%d ' % (message, addr, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((addr, port))
            s.send(message)
            reply = s.recv(14096)
            break
        except socket.error:
            s.close()
            print '[!!] Connection Error'
            break
    return reply


def create_ephemeral_key():
    if not os.path.isdir('KEYS/'):
        os.mkdir('KEYS/')
    key = RSA.generate(2048)
    private_key = key.exportKey(format='PEM', passphrase='?test!')
    file_out = open("KEYS/private.pem", "wb")
    file_out.write(private_key)
    public_key = key.publickey()

    file_out = open("KEYS/public.pem", "wb")
    file_out.write(public_key.exportKey())
    return public_key


def retrieve_peer_key(ip):
    key_file = ip.replace('.', '')+'.pem'
    try:
        encoded_key = open('KEYS/'+key_file).read()
        return RSA.importKey(encoded_key, passphrase=None)
    except:
        print '[!!] Could Not Retrieve Credentials for %s' % ip


def arr2str(args):
    string = ''
    for e in args:
        string += e
    return string


if __name__ == '__main__':
    if 'send' in sys.argv:
        addr = sys.argv[2]
        port = int(sys.argv[3])
        message = sys.argv[4]
        print send_and_wait(addr, port, message, 5)

    if 'keygen' in sys.argv:
        prk, pbk = create_ephemeral_key()

# EOF
