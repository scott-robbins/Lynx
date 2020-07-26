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
			while self.running:
				public_key = self.k.publickey()
				server_crypto = PKCS1_OAEP.new(public_key)
			
				# Accept A Client connection (Blocks Here Until recieivng a client!!)
				client, client_info = self.serve.accept()
				# Check whether new client
				client_ip = client_info[0]
				# Check whether IP is known (Diff. peers can have same IP tho! bc NAT)
				if client_info[0] not in self.known:
					# Every Client gets a unique session_id for encrypting
					sess_key = get_random_bytes(16)
					# New Clients will be sending their public key first
					rmt_pub = client.recv(2050)
					print '[*] Received %s Public Key' % (client_ip)
					# New Client so exchange Public Key Crypto
					encrypted_reply = PKCS1_OAEP.new(RSA.importKey(rmt_pub)).encrypt(sess_key)
					print '[*] Sending %s a unique session key ' % client_ip
					client.send(encrypted_reply)
					enc_name = client.recv(2048)
					# log this session key for the username they reply with 
					client_username = utils.DecodeAES(AES.new(sess_key), enc_name).replace(' ', '')
					print '[*] %s is registering as: %s' % (client_ip, client_username)
					self.known.append(client_ip)
					if client_username not in self.users.keys():
						self.users[client_username] = client_ip
						self.tokens[client_username] = sess_key
						self.crypto[sess_key] = AES.new(sess_key)
						client.send('OK')
					else:
						client.send('Username taken!')
				else:	# else it is a known client so try and handle api request
					enc_query = client.recv(2048)
					uname = enc_query.split(' !!!! ')[0]
					skey = self.tokens[uname]
					dec_query = utils.DecodeAES(AES.new(skey), enc_query.split(uname)[1])
					
					try:	
						# parse the query
						api_fcn = dec_query.split(' ???? ')[0]
						api_req = dec_query.split(' ???? ')[1]
						
						# if api_fcn is recognized, handle it 
						if api_fcn in self.actions.keys():
							print '[*] Handling API request %s' % api_fcn
							client = self.actions[api_fcn](client, client_info, api_req, uname)
					
					except IndexError:
						print '[!!] Malformed API request from %s' % client_ip
						dec_query
						pass
					
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
		clear_reply = self.dump_peers(self.users.keys())
		c.send(utils.EncodeAES(self.crypto[name], clear_reply))
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

