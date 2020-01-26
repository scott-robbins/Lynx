import utils
import time
import sys
import os

verbose = True  # TODO: DEBUG setting
date, localtime = utils.create_timestamp()
print '[{(~\033[1m LYNX CLIENT \033[0m~ )}]\t\t%s - %s' % (localtime, date)
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
key_file_name = private.replace('.', '-')+'.pem'
private_key = utils.load_private_key(key_file_name)
public_key = private_key.publickey()
# - [2] Create or Load a SHARED/ Folder
if not os.path.isdir('SHARED'):
    os.mkdir('SHARED')
    shares = []
else:
    shares = os.listdir('SHARED')
print '[*] %d files in SHARED/ Folder' % len(shares)

# Register With Main Cloud Server
print 'This is your internet login password: '
os.system('sha256sum %s >> hash.txt' % key_file_name)
login = utils.swap('hash.txt', True).pop().split(' ').pop(0)
print login
print 'You can visit %s to Login ater we are done here.' % domain
uname = str(raw_input('Enter the username you will login with: '))
open(uname+'.pass','wb').write(login)
# Update/Sync with the P2P Cloud


