import utils
import time
import sys
import os

if 'snap_n_send' in sys.argv:
    os.system('raspistill -t 1 -o im.jpeg')
    print '[*] Transferring image'
    os.system('python client.py put im.jpeg')
    os.remove('im.jpeg')
