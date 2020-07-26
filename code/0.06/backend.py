from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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
	known = []
	running = False

	def __init__ (self):
		self.actions = {'TEST': self.check_in}
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
				sess_key = get_random_bytes(32)
				# Accept A Client connection (Blocks Here Until recieivng a client!!)
				client, client_info = self.serve.accept()
				# Check whether new client
				client_ip = client_info[0]

				raw_data = client.recv(4096)
				if len(raw_data.split('-----BEGIN PUBLIC KEY-----'))> 1:
					try: 
						# This is a new client trying to setup keys 
						user_public_key = raw_data.split(' **** ')[0]
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
						api_req = dec_req.split(" ???? ")[0]
						print '[*] %s is requesting to %s' % (username, api_fcn)
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
		c.send(utils.EncodeAES(self.crypto[self.tokens[name]], clear_reply))
		return c 

	def show_peers(self, c, ci, req, name):
		clear_reply = self.dump_peers(self.tokens.keys())
		return c

	def dump_peers(cs):
		if os.path.isfile(os.getcwd()+'/LynxData/clients.txt'):
			known_clients = utils.swap(os.getcwd()+'/LynxData/clients.txt', True)
		else:
			known_clients = []
		known_clients = list(set(known_clients))
		for addr in cs:
			if addr not in known_clients and len(addr) > 1:
				known_clients.append(addr)
		# Now dump it to txt file
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

def main():
	BackendAPI()


if __name__ == '__main__':
	main()

