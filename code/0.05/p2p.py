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

def send_message(recipient, message_file):
	sent = False
	try:
		middle_man = get_server_addr()
		data = open(message_file, 'rb').read()
		api_request = 'SEND ???? %s :::: ;;;; %s ' % (recipient, data)
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((middle_man, 54123))
		s.send(api_request)
		title = '%sFOR%s' % (api_request.split(' ???? ')[1].split(' ;;;; ')[1], utils.get_ext_ip().replace('.','-'))
		print title
		reply = s.recv(1028)
		if reply == 'SUCCESS':
			sent = True
		s.close()
	except socket.error:
		print '[!!] Error Sending message'
	return sent

def send_message_custom_header(recipient, message_file, header):
	sent = False
	try:
		middle_man = get_server_addr()
		data = open(message_file, 'rb').read()
		api_request = 'SEND ???? %s :::: %s ;;;; %s' % (recipient, data, header)
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((middle_man, 54123))
		s.send(api_request)
		title = '%sFOR%s' % (api_request.split(' ???? ')[1].split(' ;;;; ')[1], utils.get_ext_ip().replace('.','-'))
		print title
		reply = s.recv(1028)
		if reply == 'SUCCESS':
			sent = True
		s.close()
	except socket.error:
		print '[!!] Error Sending Message'
	return sent

def check_msg():
	recieved = False
	try:
		middle_man = get_server_addr()
		api_request = 'CHECK ???? ::::'
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((middle_man, 54123))
		s.send(api_request)
		reply = s.recv(65535)
		print reply
		s.close()
	except socket.error:
 		print '[!!] Unable to Check Messages'
		exit()
	return recieved

def read_msg(sender):
	found = False
	try:
		localaddr = utils.get_ext_ip().replace('.','-')
		msgfile = '%sFOR%s' % (sender.replace('.','-'), localaddr)
		api_request = 'READ ???? %s' % msgfile
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((get_server_addr(), 54123))
		s.send(api_request)
		reply = s.recv(65535)
		s.close()
		print reply
	except socket.error:
		print '[!!] Unable to retrieve message'
		exit()
	return found

def get_server_addr():
	addr = utils.cmd('host beta.lynx-network.us', False).pop().split(' address ')[1]
	return addr

def check_ping():
	latency = []
	cmd = 'ping -c 3 %s' % get_server_addr()
	for line in utils.cmd(cmd, False):
		try:
			stats =  line.split('64 bytes from ')[1].split(': ')[1].split(' ')
			latency.append(float(stats[2].replace('time=','')))
		except IndexError:
			pass
	return latency

def main():
	if 'status' in sys.argv:
		# do a status check
		if check_status(get_server_addr()):
			print '[o] Connected to Remote Server'
		else:
			print '[x] Failled to Connect to Server'

if __name__ == '__main__':
	main()