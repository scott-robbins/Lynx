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
		c.send(pbkey.exportKey())
		if verbose:
			print '[*] Sent Public Key'
		encrypted_session_key = c.recv(2040)
		session_key = rsa_decrypt(encrypted_session_key)
		if verbose:
			print '[*] Recieved %d byte session key' % len(session_key)
		c.send(utils.EncodeAES(AES.new(session_key), uname))
		if c.recv(128)=='OK':
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

def connection_benchmark(uname, skey, verbose):
	dt = 0.0; secured = False; tries = 0
	try:
		t0 = time.time()
		while not secured and tries < 3:
			s = utils.create_tcp_socket(False)
			s.connect((utils.get_server_addr(), 54123))
			api_test = 'TEST ???? Hello!'
			s.send(uname +' !!!! '+utils.EncodeAES(AES.new(skey), api_test))
			enc_reply = s.recv(2048)
			s.close()
			dt = time.time()-t0
			dec_reply = utils.DecodeAES(AES.new(skey), enc_reply)
			if dec_reply == ('Hello, %s' % uname):
				print '[*] Checkin Complete'
				secured = True
			else:
				print '!! Security WARNING: %s != %s' % (dec_reply, 'Hello, %s' % uname)
			if verbose:
				print '[o] Round Trip Time: %s seconds' % str(dt)
	except socket.error:
		print '[!!] Connection Error during API Request'
	return dt, secured


def get_peers(uname, skey, verbose):
	transferred = False
	peers = []
	cipher = AES.new(skey)
	stun = utils.get_server_addr()
	
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((stun, 54123))
		payload = utils.EncodeAES(cipher, 'PEERS ???? Please')
		api_req = '%s !!!! %s' % (uname, payload)
		s.send(api_req)
		
	except
		print '[!!] Unable to complete API request'
        pass
    return transferred, peers