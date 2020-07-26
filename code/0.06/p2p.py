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

def handshake(uname, pbkey,verbose):
	success = False
	session_key = ''
	try:
		c = utils.create_tcp_socket(False)
		c.connect((utils.get_server_addr(), 54123))
		if verbose:
			print '[*] Connected to remote server'
		key_exch = pbkey + ' **** ' + uname
		c.send(key_exch)
		if verbose:
			print '[*] Sent Public Key'
		# TODO: FINISH
		# GET SERVERS PUBLIC KEY FOR FURTHER COMMUNICATIONS
		reply = c.recv(1028)
		if len(reply).split('-----BEGIN PUBLIC KEY-----') > 1:
			server_public_key = reply.split(' **** ')[0]
			session_key = reply.split(' ***** ')[1]
			print '[*] Received Public Key and Session Key'
			success = True
		c.close()
	except socket.error:
		print '!! CONNECTION ERROR: Handshake Failed '
	return success, session_key

def rsa_decrypt(enc_data):
	get_key = 'ls LynxData/*.pem'
	key_name = utils.cmd(get_key, False).pop()
	cred_name = key_name.split('.pem')[0]+'.creds'
	private_key = RSA.importKey(open(os.getcwd()+'/%s' % key_name).read())
	return PKCS1_OAEP.new(private_key).decrypt(enc_data)

