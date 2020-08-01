from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import socket
import utils
import time
import p2p
import sys 
import os

def handshake(uname,srvr, pbkey,verbose):
	success = False
	session_key = ''
	server_public_key = ''
	try:
		c = utils.create_tcp_socket(False)
		c.connect((srvr, 54123))
		if verbose:
			print '[*] Connected to remote server'
		key_exch = pbkey.exportKey() + ' **** ' + uname
		c.send(key_exch)
		if verbose:
			print '[*] Sent Public Key'
		# TODO: FINISH
		# GET SERVERS PUBLIC KEY FOR FURTHER COMMUNICATIONS
		reply = c.recv(1028)
		if len(reply.split('-----BEGIN PUBLIC KEY-----')) > 1:
			server_public_key = reply.split(' **** ')[0]
			session_key = rsa_decrypt(reply.split(' **** ')[1])
			print '[*] Received Public Key and Session Key'
			success = True
		c.close()
	except socket.error:
		print '!! CONNECTION ERROR: Handshake Failed '
	return success, session_key, server_public_key

def rsa_decrypt(enc_data):
	get_key = 'ls LynxData/Creds/*.pem'
	key_name = utils.cmd(get_key, False).pop()
	cred_name = key_name.split('.pem')[0]+'.creds'
	private_key = RSA.importKey(open(os.getcwd()+'/%s' % key_name).read())
	return PKCS1_OAEP.new(private_key).decrypt(enc_data)

def load_sess_key():
	if os.path.isfile(os.getcwd()+'/LynxData/Creds/session'):
		skey = open(os.getcwd()+'/LynxData/Creds/session', 'rb').read()
	else:
		print '[!!] NO Session Key Found'
		exit()
	return skey

def check_connection(uname, srvr, verbose):
	success = False
	timer = 0.0; start = time.time()
	session_key = load_sess_key()
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		enc_dat = utils.EncodeAES(AES.new(base64.b64decode(session_key)),'TEST ???? Hello')
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		reply = utils.DecodeAES(AES.new(base64.b64decode(session_key)), s.recv(1025))
		print reply
		if reply == 'Hello, %s' % uname:
			success = True
			timer = time.time() - start
			if verbose:
				print '[*] API Request Replied to in %s seconds' % str(timer)
		s.close()
	except socket.error:
		print 'Error Making API Request'
		pass
	return success, time

def show_peers(uname, srvr, verbose):
	success = False
	session_key = load_sess_key()
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		enc_dat = utils.EncodeAES(AES.new(base64.b64decode(session_key)), 'PEERS ???? List')
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		peer_list = utils.DecodeAES(AES.new(base64.b64decode(session_key)), s.recv(15535)).split('\n')
		print peer_list
		success = True
		s.close()
	except socket.error:	
		print 'Error Making API Request'
		pass
	return success, peer_list		

def message_peer(uname, srvr, recipient, payload, verbose):
	completed = False
	session_key = load_sess_key()
	locald, localt = utils.create_timestamp()
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		cmesg = 'POKES ???? %s @ %s - %s :::: %s ;;;;' % (recipient, locald, localt, payload)
		enc_dat = utils.EncodeAES(AES.new(base64.b64decode(session_key)), cmesg)
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		sum = int(s.recv(100))
		s.close()
		if sum == len(payload):
			completed = True
		else:
			print sum
	except socket.error:	
		print 'Error Making API Request'
		pass	
	return completed

def show_inbox(uname, srvr, verbose):
	new_messages = False
	messages = []
	session_key = load_sess_key()
	ciph = AES.new(base64.b64decode(session_key))
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		cmesg = 'INBOX ???? List'
		enc_dat = utils.EncodeAES(ciph, cmesg)
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		print '[*] Requesting to see Inbox'
		messages = utils.DecodeAES(ciph, s.recv(65535)).split('\n')
		messages.pop(-1)
		if len(messages) >= 1:
			new_messages = True
			if verbose:
				print '[*] You Have %d new messages' % len(messages)
				for m in messages:
					print '\to %s' % m
		s.close()
	except socket.error:
		print 'Error Making API Request'
		pass

	return new_messages, messages

def read_message(uname, srvr, message_name, verbose):
	recvd = False; content = ''
	session_key = load_sess_key()
	ciph = AES.new(base64.b64decode(session_key))
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		cmesg = 'READ ???? %s' % message_name
		enc_dat = utils.EncodeAES(ciph, cmesg)
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		print '[*] Requesting to read %s' % message_name
		content = utils.DecodeAES(ciph, s.recv(65535)).replace(' ;;;; ', '\n')
		if content != '!! unable to read message !!':
			recvd = True
			if verbose:
				print '[*] Retrieved %s:\n%s' % (message_name, content)
		else:
			content = ''
	except socket.error:
		print 'Error Making API Request'
		pass
	s.close()
	return recvd, content

def delete_message(uname, srvr, message_name, verbose):
	deleted = False
	bytes_deleted = 0
	session_key = load_sess_key()
	ciph = AES.new(base64.b64decode(session_key))
	
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr,54123))
		cmesg = 'REMOVE ???? %s' % message_name
		enc_dat = utils.EncodeAES(ciph, cmesg)
		api_req = '%s !!!! %s' % (uname, enc_dat)
		s.send(api_req)
		print '[*] Requesting to delete %s' % message_name
		result = utils.DecodeAES(ciph,s.recv(256))
		if result.split(' ')[0]=='Deleted':
			print result
			bytes_deleted = int(result.split('Deleted ')[1].split(' bytes')[0])
		else:
			print result.upper()
	except socket.error:
		print 'Error Making API Request'
		pass
	s.close()
	return deleted, bytes_deleted

def tag_file_for_sharing(funame, srvr, file_path, verbose):
	uploaded = False
	file_tag = ''
	file_name = file_path.split('/')[-1]
	if not os.path.isdir(os.getcwd()+'/LynxData/Shared'):
		os.mkdir(os.getcwd()+'/LynxData/Shared')
	hash = utils.cmd('sha256sum %s' % file_path, False).pop().split(' ')[0]
	size = os.path.getsize(file_path)

	session_key = load_sess_key()
	ciph = AES.new(base64.b64decode(session_key))

	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		cmesg = 'TAGFILE ???? %s :::: %s ;;;; %d' % (file_name, hash, size)
		enc_data = utils.EncodeAES(ciph, cmesg)
		api_req = '%s !!!! %s' % (uname, cmesg)
		s.send(api_req)
		print '[*] Adding %s <%s> to shared uploads' % (file_name, hash)
		s.send(enc_dat)
		reply = s.recv(1028)
		if utils.DecodeAES(ciph, reply) == hash:
			uploaded = True
		else:
			print '[!!] Server Replied with Incorrect File Hash:\n%s' % reply
	except socket.error:
		print 'Error Making API Request'
		pass
	s.close()
	
	return uploaded, file_tag

def start_proxy(uname, srvr, rmt_host, rmt_port):
	proxying = False
	session_key = load_sess_key()
	ciph = AES.new(base64.b64decode(session_key))
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		cmesg = 'SET_PROXY ???? %s :::: %s' % (rmt_host, rmt_port)
		enc_dat = utils.EncodeAES(ciph, cmesg)
		api_req = '%s !!!! %s' % (uname, enc_dat)
		# Request to start proxying
		print cmesg
		s.send(api_req)
		print '[*] Requesting to%s' % (cmesg)
		reply = utils.DecodeAES(ciph, s.recv(2048))
		if len(reply.split(':'))==2:
			proxying = True
			print '[*] Proxy Flag Set on MiddleManServer for %s:%s' % (rmt_host, rmt_port) 
		else:
			print '[!!] Error Setting Proxy Flag'
			print reply
	except socket.error:
		print 'Error Making API Request'
		pass
	s.close()
	return proxying

