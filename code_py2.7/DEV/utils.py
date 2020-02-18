from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import paramiko
import socket
import base64
import time
import sys
import os

BLOCK_SIZE = 16     # the block size for the cipher object; must be 16 per FIPS-197
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        # pad text to be encrypted
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))            # encrypt with AES
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


def create_timestamp():
    date = time.localtime(time.time())
    mo = str(date.tm_mon)
    day = str(date.tm_mday)
    yr = str(date.tm_year)

    hr = str(date.tm_hour)
    min = str(date.tm_min)
    sec = str(date.tm_sec)

    date = mo + '/' + day + '/' + yr
    timestamp = hr + ':' + min + ':' + sec
    return date, timestamp


def swap(file_name, destroy):
    data = []
    for line in open(file_name, 'r').readlines():
        data.append(line.replace('\n', ''))
    if destroy:
        os.remove(file_name)
    return data


def cmd(shell):
    os.system('%s >> tmp.txt' % shell)
    return swap('tmp.txt', True)


def arr2str(arr):
    content = ''
    for e in arr:
        content += e + ' '
    return content


def arr2lines(arr):
    content = ''
    for line in arr:
        content += line + '\n'
    return content


def start_listener(port, timeout):
    started = False
    while not started:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print '[!!] Unable to create listener'
            time.sleep(timeout)
        try:
            s.bind(('0.0.0.0', port))
            s.listen(5)
            started = True
        except socket.error:
            print '[!!] Unable to create listener'
            s.close()
            time.sleep(timeout)
    return s


def crawl_dir(file_path, h, verbose):
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
                if h:
                    hashes['"'+file_name+'"'] = get_sha256_sum(file_name.replace('//','/'), False)
                if verbose:
                    print '\033[3m- %s Added to Shared Folder\033[0m' % file_name
            else:
                directory['dir'].append(direct + '/' + item)
                folders.append(direct + '/' + item)
    return directory, hashes


def get_sha256_sum(file_name, verbose):
    if len(file_name.split("'"))>=2:
        file_name = ("{!r:}".format(file_name))
        os.system("sha256sum "+file_name + ' >> out.txt')
    else:
        os.system("sha256sum '%s' >> out.txt" % file_name)
        sum_data = swap('out.txt', True).pop().split(' ')[0]
        print file_name
    if verbose:
        print sum_data
    return sum_data


def get_nx_info(verbose):
    os.system('sh get_network_addresses.sh')
    for line in swap('nx.txt', True):
        try:
            public = line.split('Public IP:')[1].replace('\t', '').replace('\n', '')
        except IndexError:
            pass
        try:
            local = line.split('Private IP:')[1].replace('\t', '').replace('\n', '')
        except IndexError:
            pass
        try:
            iface = line.split('Nx Iface:')[1].replace('\t', '').replace('\n', '')
        except IndexError:
            pass
    if verbose:
        print 'Public IP: %s' % public
        print 'Internal IP: %s' % local
        print 'NX Interface: %s' % iface
    return public, local, iface


# ############################ CRYPTOGRAPHIC FUNCTIONS ############################ #
def encrypt_file(content, file_name_out):
    key = get_random_bytes(32)
    key_file = file_name_out.split('.')[0]+'.key'
    encrypted_data = EncodeAES(AES.new(key), content)
    open(file_name_out, 'wb').write(encrypted_data)
    open(key_file, 'wb').write(base64.b64encode(key))


def decrypt_file(file_name, file_out, destroy):
    key_file = file_name.split('.')[0]+'.key'
    key = base64.b64decode(open(key_file,'rb').read())
    encrypted_data = open(file_name, 'rb').read()
    decrypted_data = DecodeAES(AES.new(key),encrypted_data)
    if destroy:
        os.remove(key_file)
        os.remove(file_name)
    open(file_out, 'wb').write(decrypted_data)


def create_rsa_key(name):
    key = RSA.generate(2048)
    open('%s' % name, 'wb').write(key.exportKey('PEM'))
    return key


def load_private_key(name):
    if os.path.isfile(name):
        private_key = RSA.importKey(open(name, 'rb').read())
    else:
        private_key = create_rsa_key(name)
    return private_key


# ############################ NETWORKING FUNCTIONS ############################ #
def parse_ping(result):
    open('ping.txt', 'wb').write(result)
    routable = False
    ping_time = 0
    for line in swap('ping.txt', True):
        try:
            ping_time = float(line.split('time=')[1].split(' ')[0])
            routable = True
        except IndexError:
            pass
    return routable, ping_time


import warnings                                       # SUPRESSING PARAMIKO WARNINGS!
warnings.filterwarnings(action='ignore',module='.*paramiko.*')


def ssh_command(ip, user, passwd, command, verbose):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    response = ''
    try:
        client.connect(ip, username=user, password=passwd)
        ssh_session = client.get_transport().open_session()
        response = ''
        if ssh_session.active:
            ssh_session.exec_command(command)
            response = ssh_session.recv(16777216)  # needed for file sharing
            if verbose:
                print '%s@%s:~$ %s [Executed]' % (user, ip, command)
                print '%s@%s:~$ %s' % (user, ip, response)
                return response
    except paramiko.ssh_exception.NoValidConnectionsError:
        print "Could not connect to %s" % ip
    return response


def ssh_command_no_recv(ip, uname, pw, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=uname, password=pw)
        ssh_sess = client.get_transport().open_session()
        if ssh_sess.active:
            ssh_sess.exec_command(command)
    except paramiko.ssh_exception.NoValidConnectionsError:
        print '[!!] Could not connect to %s' % ip


if 'ssh' in sys.argv and len(sys.argv) >= 5:
    user = sys.argv[2].split('@')[0]
    ip = sys.argv[2].split('@')[1]
    passwd = sys.argv[3]
    cmd = arr2str(sys.argv[4:])
    result = ssh_command(ip, user, passwd, cmd, )
    print '$ %s' % cmd
    print '$ %s' % result
