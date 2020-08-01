from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import socket 
import utils 
import time 
import sys 
import os 


class BackendAPI:
	inbound = 54123
	users = {}
	tokens = {}
	crypto = {}
	known_clients = []
	proxy_mapping = {}
	running = False

	def __init__ (self):
		# Define API Functions 
		self.actions = {'TEST':  self.check_in,
						'PEERS': self.show_peers,
						'POKES': self.poke_client,
						'INBOX': self.list_messages,
						'READ':  self.read_message,
						'REMOVE': self.delete_message,
						'SET_PROXY': self.set_proxy_flag}
		# Setup the server
		self.serve = utils.start_listener(self.inbound)
		self.k = self.setup()
		self.run()

	def setup(self):
		# Create Initial LynxData folder if not present
		if not os.path.isdir(os.getcwd()+'/LynxData'):
			os.mkdir('LynxData')
			os.mkdir('LynxData/Creds')
		if not os.path.isfile(os.getcwd()+'/LynxData/Creds/server.pem'):
			k = RSA.generate(2048)
			file_out = open(os.getcwd()+'/LynxData/Creds/server.pem', 'wb')
			file_out.write(k.exportKey('PEM'))
		else:
			k = self.load_server_key()

		return k 

	def load_server_key(self):
		return RSA.importKey(open(os.getcwd()+'/LynxData/Creds/server.pem').read())

	def run(self):
		self.running = True 
		start_t, start_d = utils.create_timestamp()
		print '\033[1m[*] Starting \033[32mLYNX BackendAPI\033[0m\033[1m'\
			  ' Server %s - %s [*]\033[0m' % (start_d, start_t)
		
		try:
			public_key = self.k.publickey()
			server_crypto = PKCS1_OAEP.new(public_key)
			while self.running:
				sess_key = get_random_bytes(16)
				# Accept A Client connection (Blocks Here Until recieivng a client!!)
				client, client_info = self.serve.accept()
				# Check whether new client
				client_ip = client_info[0]

				raw_data = client.recv(4096)
				if len(raw_data.split('-----BEGIN PUBLIC KEY-----'))> 1:
					try: 
						# This is a new client trying to setup keys 
						user_public_key = RSA.importKey(raw_data.split(' **** ')[0])
						username = raw_data.split(' **** ')[1]
						print '[*] Recieved Public Key from User %s' % username
						enc_sess_key = PKCS1_OAEP.new(user_public_key).encrypt(base64.b64encode(sess_key))
						reply = '%s **** %s' % (public_key.exportKey(), enc_sess_key)
						client.send(reply)
						self.tokens[username] = sess_key 
						self.crypto[sess_key] = AES.new(sess_key)
					except IndexError:
						print '!! Malformed API request'
						pass
				elif len(raw_data.split(' !!!! ')) > 1:  # They are encrypted with users session key
					username = raw_data.split(' !!!! ')[0]
					enc_req = raw_data.split(' !!!! ')[1]
					# make sure user is known before trying to decrypt api request
					if username in self.tokens.keys():
						dec_req = utils.DecodeAES(AES.new(self.tokens[username]), enc_req)
						api_fcn = dec_req.split(' ???? ')[0]
						api_req = dec_req.split(" ???? ")[1]
						print '[*] %s is requesting to %s' % (username, api_fcn)
						if api_fcn == 'REMOVE':
							print dec_req
						# known fcn run it 
						if api_fcn in self.actions.keys():
							client = self.actions[api_fcn](client, client_info, api_req, username)


				# Close the connection 
				client.close()
		except KeyboardInterrupt:
			self.shutdown
			try:
				client.close()
			except socket.error:
				pass

	def check_in(self, c, ci, req, name):
		clear_reply ='Hello, %s' % name 
		self.known_clients.append(name)
		c.send(utils.EncodeAES(self.crypto[self.tokens[name]], clear_reply))
		return c 

	def show_peers(self, c, ci, req, name):
		clear_reply = self.dump_peers(self.known_clients)
		c.send(utils.EncodeAES(self.crypto[self.tokens[name]], clear_reply))
		return c

	def dump_peers(self, cs):
		if os.path.isfile(os.getcwd()+'/LynxData/clients.txt'):
			known_clients = utils.swap(os.getcwd()+'/LynxData/clients.txt', True)
		else:
			known_clients = []
		known_clients = list(set(known_clients))
		for addr in cs:
			if addr not in known_clients and len(addr) > 1:
				known_clients.append(addr)
		# Now dump it to txt file
		cs.pop(-1)
		dump = ''
		for ln in cs:
			dump += ln + '\n'
		# Rewrite the data because we erased old file and added new clients
		open(os.getcwd()+'/LynxData/clients.txt', 'wb').write(dump)
		return	dump

	def shutdown(self):
		self.running = False
		self.serve.close()
		end_t, end_d = utils.create_timestamp()
		self.dump_peers(self.tokens.keys())
		print '[!!] Server Killed [%s - %d]' % (end_d, end_t)

	def poke_client(self, c, ci, req, name):
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging'):
			os.mkdir(os.getcwd()+'/LynxData/messaging')
		for uname in self.tokens.keys():
			if not os.path.isdir(os.getcwd()+'/LynxData/messaging/' + uname):
				os.mkdir(os.getcwd()+'/LynxData/messaging/' + uname)
		try:
			recvr = req.split(' @ ')[0]
			date = req.split(' - ')[0].split(recvr)[1]
			ltime = req.split(' - ')[1].split(' :::: ')[0]
			message = req.split(' :::: ')[1].split(' :::: ')[0]
			if recvr in self.tokens.keys():
				print '%s is sending a message for %s at %s - %s:' % (name, recvr, date, ltime)
				msg_dat = 'From: %s\nSent: %s  %s\nMessage: \n%s' % (name, date, ltime, message)
				when = date.replace('/','').replace('@','').replace(' ','')+'_'+ltime.replace(':', '')
				# Adding this because a client might send more than one message a second!!
				quick_hash = SHA256.new()
				quick_hash.update(msg_dat)
				msg_id = ''.join(base64.b64encode(quick_hash.digest()[0:16])[0:8])
				name = '%sFOR%sAT%s_%s.msg' % (name,recvr,when, msg_id)
				# Write the message to disk
				open(os.getcwd()+'/LynxData/messaging/%s/%s' % (recvr, name), 'wb').write(msg_dat)
				c.send(str(len(message)))
			else:
				print recvr
				print '%s tried sending an undeliverable message' % name
				c.send('0')		
		except IndexError:
			print '[!!] Error receivng message'
			print name
			print req
		return c

	def list_messages(self, c, ci, req, name):
		cipher = self.crypto[self.tokens[name]]
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging'):
			os.mkdir(os.getcwd()+'/LynxData/messaging')
			c.send(utils.EncodeAES(cipher, 'You Have 0 New Messages'))
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging/%s' % name):
			os.mkdir(os.getcwd()+'/LynxData/messaging/%s' % name)
			c.send(utils.EncodeAES(cipher, 'You Have 0 New Messages'))
		else:
			show = 'ls %s' % (os.getcwd()+'/LynxData/messaging/%s' % name)
			names = utils.arr2str(utils.cmd(show, False))
			c.send(utils.EncodeAES(cipher, names))
		return c

	def read_message(self, c, ci, req, name):
		cipher = self.crypto[self.tokens[name]]
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging'):
			os.mkdir(os.getcwd()+'/LynxData/messaging')
			c.send(utils.EncodeAES(cipher, '!! unable to read message !!'))
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging/%s' % name):
			os.mkdir(os.getcwd()+'/LynxData/messaging/%s' % name)
			c.send(utils.EncodeAES(cipher, '!! unable to read message !!'))
		else:
			show = 'ls %s' % (os.getcwd()+'/LynxData/messaging/%s' % name)
			mname = os.getcwd()+'/LynxData/messaging/%s/%s' % (name, req)
			if req in utils.cmd(show, False):
				print '[*] %s is reading %s' % (name, req)
				c.send(utils.EncodeAES(cipher, open(mname, 'rb').read()))
			else:
				c.send(utils.EncodeAES(cipher, '!! unable to read message !!'))
		return c

	def delete_message(self, c, ci, req, name):
		cipher = self.crypto[self.tokens[name]]
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging/'):
			os.mkdir(os.getcwd()+'/LynxData/messaging')
			c.send(utils.EncodeAES(cipher, '!! unable to delete message !!'))
			return c
		if not os.path.isdir(os.getcwd()+'/LynxData/messaging/%s' % name):
			os.mkdir(os.getcwd()+'/LynxData/messaging/%s' % name)
			c.send(utils.EncodeAES(cipher, '!! unable to delete message !!'))
			return c
		if os.path.isfile(os.getcwd()+'/LynxData/messaging/%s/%s'%(name, req)):
			content = open(os.getcwd()+'/LynxData/messaging/%s/%s'%(name, req),'rb').read()
			sz = len(content)
			print sz
			os.remove(os.getcwd()+'/LynxData/messaging/%s/%s'%(name, req))
			c.send(utils.EncodeAES(cipher, 'Deleted %d bytes' % sz))
		else:
			c.send(utils.EncodeAES(cipher, '!! unable to delete message !!'))
		return c

	def add_file_tag(self, c, ci, req, name):
		
		return c

	def set_proxy_flag(self, c, ci, req, name):
		cipher = self.crypto[self.tokens[name]]
		try:
			proxy_endpt = req.split(' :::: ')[0]
			proxy_port = req.split(' :::: ')[1]
		except IndexError:
			print '[!!] Malformed API query'
			return c
		try:
			if proxy_endpt in self.tokens.keys():
				self.proxy_mapping[client] = [ci[0], proxy_endpt, proxy_port]
				c.send(utils.EncodeAES(cipher, 'Proxy Flag Set for: %s:%s' % (proxy_endpt, proxy_port)))
			else:
				c.send(utils.EncodeAES(cipher, 'Unknown Client %s, cannot set proxy flag' % proxy_endpt))
		except socket.error:
			print '[!!] Connection Error'
			pass
		return c


def main():
	BackendAPI()


if __name__ == '__main__':
	main()

