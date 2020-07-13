from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket
import utils 
import sys
import os



def check_status(ip_addr):
	connected = False
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip_addr, 54123))
		# TODO: Add encryption/handshake here
		msg = 'API_REQUEST_BASIC' 
		s.send('STATUS ???? %s' % msg)
		# status heck simply wants to see this token echoed back
		reply = s.recv(1024)
		if reply == msg:
			connected = True
		else:
			print 'Sent: %s' % msg
			print 'Got: %s' % reply
		s.close()
	except:
		print '[!!] Error Making API Request'
		pass
	return connected

def get_server_addr():
	addr = utils.cmd('host beta.lynx-network.us', False).pop().split(' address ')[1]
	return addr

if 'status' in sys.argv:
	# do a status check
	if check_status(get_server_addr()):
		print '[o] Connected to Remote Server'
	else:
		print '[x] Failled to Connect to Server'