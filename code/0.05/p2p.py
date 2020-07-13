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
		s.send('STATUS ???? API_REQUEST_BASIC')
		token = s.recv(1024)
		# status heck simply wants to see this token echoed back
		s.send(token)
		if s.recv(1024) == 'OK, Message Recieved':
			connected = True
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