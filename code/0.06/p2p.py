from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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

def check_connection(uname, srvr, verbose):
	success = False
	timer = 0.0; start = time.time()
	if os.path.isfile(os.getcwd()+'/LynxData/Creds/session'):
		session_key = open(os.getcwd()+'/LynxData/Creds/session', 'rb').read()
	else:
		print '[!!] NO Session Key Found'
		exit()
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
	except socket.error:
		print 'Error Making API Request'
		pass
	return success, time

def show_peers(uname, srvr, verbose):
	success = False
	if os.path.isfile(os.getcwd()+'/LynxData/Creds/session'):
		session_key = open(os.getcwd()+'/LynxData/Creds/session', 'rb').read()
	else:
		print '[!!] NO Session Key Found'
		exit()
	try:
		s = utils.create_tcp_socket(False)
		s.connect((srvr, 54123))
		enc_dat = utils.EncodeAES(AES.new(base64.b64decode(session_key)), 'PEERS ???? List')
		s.send(enc_dat)
		peer_list = utils.DecodeAES(AES.new(base64.b64decode(session_key)), s.recv(15535)).split('\n')
		print peer_list
		success = True
	except socket.error:	
		print 'Error Making API Request'
		pass
	return success, peer_list		