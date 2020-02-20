import utils
import time
import sys
import os

if 'snap_n_send' in sys.argv:
    cmd = 'for i in {1..1000}; do ' \
          'rm im.jpeg;' \
          ' raspistill -t 1 -o im.jpeg;' \
          ' python client.py put im.jpeg;' \
          ' sleep 1800;' \
          ' done'
    os.system(cmd)
