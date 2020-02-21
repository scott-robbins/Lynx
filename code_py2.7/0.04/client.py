from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
try:
    from tqdm import tqdm
    progress_bar = True
except ImportError:
    progress_bar = False
    pass
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
    print '[*] %d files in Local SHARED/ Folder' % len(shares)
    return priv, pub, shares


def get_file(fname, mykey):
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
        n_recv = 0; n_throw = 3
        if progress_bar:
            progress = tqdm(total=n_fragments, unit=' packets')
        else:
            progress = ''
        while not recombined or n_throw < 0:
            try:
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((cloud_gateway, 54124))
                raw_chunk = s.recv(2048)
                s.send('GOT:%d' % len(raw_chunk))
                s.close()
                open('chunk%d.frag' % n_recv, 'wb').write(utils.DecodeAES(cipher, raw_chunk))
                if progress_bar:
                    progress.update(1)
                else:
                    progress = int(n_recv/n_fragments)*'#'
                n_recv += 1
                # print '*Debug: %d fragments receieved' % n_recv
                if n_recv == n_fragments:
                    break
            except socket.error:
                time.sleep(1)
                n_throw -= 1
                pass
                print '[!!] Failed to create socket... Are you running as root?'
        if progress_bar:
            progress.close()
        print '[*] Recombining %d fragments' % n_recv
        target = 'SHARED/%s' % fname
        content = ''
        for i in range(0, n_fragments):
            content += open('chunk%d.frag' % i, 'rb').read()
        os.system('rm *.frag')
        open(target, 'wb').write(content)
        os.system('sha256sum %s' % target)
        print '[*] %d Fragments Received and Recombined into %s [%d bytes]' % \
              (n_fragments, fname, file_size)

    return len(encr)


def put_file(fname, mykey):
    enc_data = utils.EncodeAES(cipher, open(fname, 'rb').read())
    size = len(enc_data)
    query = 'PUT_%s_%s' % (fname, size)
    # print '[*] Querying %s...' % query
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

    if 'peers' in sys.argv:  # show registed peers using api key
        show_peers(my_api_key)

    if 'shares' in sys.argv:
        show_shared(my_api_key)

    if 'put' in sys.argv and len(sys.argv) >= 3:
        if not os.path.isfile(sys.argv[2]):
            print '[!!] Cannot find file %s' % sys.argv[2]
        else:
            print '[*] Uploading %s to Lynx Cloud' % sys.argv[2]
        n = sys.argv[2]
        sz = os.path.getsize(n)
        if sz > 1500:
            fragments = network.fragmented(n, 800)
            # TODO: Alert remote host about fragments coming
            msg = utils.EncodeAES(cipher, 'incoming_file:%s' % n)
            network.connect_send(cloud_gateway, 54123, my_api_key+' ???? '+msg,10)
            print '[*] File is %d bytes (over 1.5kB)' % sz
            print '[*] Fragmenting into %d Files...' % len(fragments['frags'])

            N = 0
            if progress_bar:
                for file_name in tqdm(fragments['frags'], unit=' fragments'):
                    put_file(file_name, my_api_key)
                    N += 1
            else:
                for file_name in fragments['frags']:
                    put_file(file_name, my_api_key)
                    N+=1
            os.system('rm -r chunks/')
            encr = utils.EncodeAES(cipher, 'fragments:%d = %s' % (N, n))
            network.connect_send(cloud_gateway, 54123, my_api_key + ' ???? '+encr, 10)
        else:
            put_file(n, my_api_key)
        print 'File Transferred. File Data:\n'
        os.system('sha256sum %s' % n)

    if 'get' in sys.argv and len(sys.argv) >= 3:
        n = sys.argv[2]
        get_file(n,my_api_key)

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

    if 'set_cam' in sys.argv:
        encr = utils.EncodeAES(cipher, 'cam_ready')
        network.connect_send(cloud_gateway, 54123, my_api_key + ' ???? ' + encr, 10)

    if 'browser' in sys.argv:
        # try firefox first, if that doesnt work try chrome
        try:
            os.system('sh $(firefox %s:80)&' % cloud_gateway)
        except OSError:
            # TODO: try chrome
            pass

    if 'run' in sys.argv:
        # Synchronize SHARED folder with cloud
        os.system('python client.py shares >> shared.txt')
        dat = utils.swap('shared.txt', True)
        dat.pop(0)
        dat.pop(0)
        dat.pop(0)
        shared = {}
        for line in dat:
            try:
                f_hash = line.split(' ')[0]
                if len(f_hash) > 1:
                    f_name = line.split(f_hash)[1]
                    shared[f_hash] = f_name
            except IndexError:
                pass

        direct, hashed = utils.crawl_dir('SHARED',True,False)
        if len(hashed.keys()) > len(shared.keys()):
            for local in hashed.keys():
                key = hashed[local]
                if key not in shared.keys() and len(key)>11:
                    print '[*] %s is not in local Shared/' % hashed[key]
        elif len(hashed.keys()) < len(shared.keys()):
            for remote_key in shared.keys():
                if remote_key not in hashed.values() and len(remote_key)>11:
                    print '[*] %s is not in local Shared/' % shared[remote_key]
                    get_file(shared[remote_key].split('../SHARED/')[1], my_api_key)
        # check routing to each peer

    if 'camera' in sys.argv:
        # not a typical client, but utilizes the same resources for communication
        callback = utils.start_listener(56234, 5)
        running = True;
        runtime = 60 * 60 * 24 * 7
        start = time.time()
        ticks = 0

        # Load Camera Config (This code will not necessarily work on other client installs)
        utils.decrypt_file('camera.config', 'camera_data.config', False)
        cam_pass = ''
        cam_name = ''
        cam_ip = ''
        for line in utils.swap('camera_data.config', True):
            try:
                cam_ip = line.split('ip:')[1]
            except IndexError:
                pass
            try:
                cam_pass = line.split('password:')[1]
            except IndexError:
                pass
            try:
                cam_name = line.split('username:')[1]
            except IndexError:
                pass
        try:
            print 'Starting CameraFeed'
            while running and (time.time() - start) < runtime:
                if int(time.time()-start) % 600 == 0:
                    snap_cmd = 'sshpass -p %s ssh %s@%s raspistill -t 1 -o im.jpeg' % \
                               (cam_pass, cam_name, cam_ip)
                    get_cmd = 'sshpass -p %s sftp %s@%s:/home/%s/im/jpeg' % \
                              (cam_pass, cam_name, cam_ip, cam_name)
                    os.system('python client.py put im.jpeg')
                    time.sleep(0.5)

        except KeyboardInterrupt:
            end_date, end_time = utils.create_timestamp()
            callback.close()
            running = False
            print '[!!] Server Killed! [%s - %s]' % (end_date, end_time)
            pass

