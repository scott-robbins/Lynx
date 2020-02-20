import utils
import time
import sys
import os

if 'snap_n_send' in sys.argv:
    print '[*] Transferring image to the cloud'
    os.system('python client.py put im.jpeg')
    os.remove('im.jpeg')
